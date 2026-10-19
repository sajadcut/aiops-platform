"""Universal read-only downstream dependency investigation on trusted VM MCP edge.

Requires service identity and systemd-verified config-file path. Models never
provide targets. No config values, credentials, raw logs or HTTP bodies escape.
"""
from __future__ import annotations
import base64
import shlex
from typing import Any

from integrations.vm.dependency_discovery import discover, load_config
from integrations.vm.general_config_review import checked_config_path, remote_config_read_command

MAX_FILES = 4
MAX_CHECKS = 6
MAX_ENCODED = 349528
SUPPORTED = (".json", ".yaml", ".yml", ".properties", ".ini", ".cfg", ".conf", ".xml", ".config")


async def http_head(connector: Any, target: str, *, host: str, port: int, scheme: str) -> dict:
    """HEAD '/' only, no auth, redirects, proxy, body or user-provided URL path."""
    connector._validate_remote_host(host)
    port = connector._validate_port(port)
    if scheme not in {"http", "https"}:
        return {"supported": False, "http_status": None, "tls_verified": None}
    # Host comes from verified config and was validated again before quoting.
    uri = scheme + "://" + host + ":" + str(port) + "/"
    cmd = (
        "if ! command -v curl >/dev/null 2>&1; then printf 'unsupported'; "
        "else curl --head --silent --show-error --max-time 5 --connect-timeout 3 "
        "--max-redirs 0 --noproxy '*' --output /dev/null "
        "--write-out '%{http_code} %{ssl_verify_result}' -- "
        + shlex.quote(uri) + " 2>/dev/null; fi"
    )
    try:
        result = await connector._run(target, cmd)
        output = str(result.get("stdout") or "").strip()
        if output == "unsupported":
            return {"supported": False, "http_status": None, "tls_verified": None}
        fields = output.split()
        code = int(fields[0]) if fields and fields[0].isdigit() else None
        tls_code = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None
        if not result.get("success") or code is None or code < 100 or code > 599:
            return {"supported": True, "http_status": None, "tls_verified": None}
        return {"supported": True, "http_status": code,
                "tls_verified": (tls_code == 0 if scheme == "https" else None)}
    except Exception:
        return {"supported": False, "http_status": None, "tls_verified": None}


async def investigate(connector: Any, target: str, service: str) -> dict:
    connector._validate_target(target)
    connector._validate_service(service)
    baseline = {
        "success": False, "target": target, "service": service,
        "status": "not_verified", "diagnostic": "dependency_investigation",
        "read_only": True, "execution_authority": False, "root_cause_confirmed": False,
        "application_health_verified": False, "protocol_health_verified": False,
        "config_contents_exposed": False, "secrets_exposed": False,
        "config_files_checked": 0, "checks_executed": 0, "dependencies": [],
        "limitations": ["network_probe_not_equal_protocol_health"],
    }
    try:
        discovered = await connector.service_config_discovery(target, service)
    except Exception:
        return {**baseline, "status": "config_discovery_unavailable"}
    if discovered.get("success") is not True:
        return {**baseline, "status": "config_discovery_unavailable"}
    base = {**baseline, "success": True}
    # No guessed file based solely on an LLM name or generic filesystem scan.
    filenames = [
        row["path"] for row in (discovered.get("files") or [])[:24]
        if isinstance(row, dict) and row.get("verified_exists") is True
        and isinstance(row.get("path"), str)
        and row["path"].lower().endswith(SUPPORTED)
    ]
    if not filenames:
        return {**base, "status": "no_verified_config_files",
                "limitations": ["systemd_config_path_not_verified"]}
    known = []
    read_failed = 0
    for path in list(dict.fromkeys(filenames))[:MAX_FILES]:
        try:
            cmd = remote_config_read_command(checked_config_path(path))
            response = await connector._run(target, cmd)
            if response.get("success") is not True:
                read_failed += 1
                continue
            encoded = str(response.get("stdout") or "").strip()
            if not (4 <= len(encoded) <= MAX_ENCODED):
                read_failed += 1
                continue
            raw = base64.b64decode(encoded, validate=True)
            if not (1 <= len(raw) <= 262144):
                read_failed += 1
                continue
            config = load_config(raw.decode("utf-8-sig"), path)
            base["config_files_checked"] += 1
            for item in discover(config):
                if item not in known and len(known) < MAX_CHECKS:
                    known.append(item)
        except Exception:
            # No parser trace or input excerpts: they can contain credentials.
            read_failed += 1
    base["config_files_failed"] = read_failed
    if not known:
        base["status"] = ("dependency_not_discovered" if base["config_files_checked"]
                          else "config_read_unavailable")
        base["limitations"] = ["no_static_dependency_endpoint_verified"]
        return base
    for dependency in known:
        record = dict(dependency)
        try:
            if record["probe"] == "http_head":
                http = await http_head(
                    connector, target, host=record["host"],
                    port=record["port"], scheme=record["kind"],
                )
                record["probe_supported"] = http["supported"]
                record["http_status"] = http["http_status"]
                record["tls_verified"] = http["tls_verified"]
                record["probe_status"] = (
                    "http_responded" if http["http_status"] is not None else
                    "unsupported" if not http["supported"] else "unavailable"
                )
            else:
                tcp = await connector.tcp_check(target, record["host"], record["port"])
                record["probe_supported"] = (tcp.get("success") is True
                                             and tcp.get("supported") is True)
                reached = tcp.get("reachable") if record["probe_supported"] else None
                record["tcp_reachable"] = reached if type(reached) is bool else None
                record["probe_status"] = (
                    "tcp_reachable" if record["tcp_reachable"] is True else
                    "tcp_unreachable" if record["tcp_reachable"] is False else
                    "unverified"
                )
        except Exception:
            record["probe_supported"] = False
            record["probe_status"] = "check_unavailable"
        base["checks_executed"] += 1
        base["dependencies"].append(record)
    base["status"] = "checks_completed"
    return base
