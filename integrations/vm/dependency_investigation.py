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
from integrations.vm.protocol_diagnostics import redis_unauthenticated_ping

MAX_FILES = 4
MAX_CHECKS = 6
MAX_ENCODED = 349528
SUPPORTED = (".json", ".yaml", ".yml", ".toml", ".properties", ".ini", ".cfg", ".cnf", ".conf", ".xml", ".config")


async def http_head(connector: Any, target: str, *, host: str, port: int, scheme: str) -> dict:
    """HEAD '/' only, no auth, redirects, proxy, body or user-provided URL path."""
    connector._validate_remote_host(host)
    port = connector._validate_port(port)
    if scheme not in {"http", "https"}:
        return {"supported": False, "http_status": None, "tls_verified": None}
    # Host comes from verified config and was validated again before quoting.
    uri_host = "[" + host + "]" if ":" in host else host
    uri = scheme + "://" + uri_host + ":" + str(port) + "/"
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
        "config_files_read": 0, "config_files_checked": 0,
        "config_files_parse_failed": 0, "checks_executed": 0, "dependencies": [],
        "limitations": ["network_probe_not_equal_protocol_health"],
        "investigation_status": "not_started", "next_checks": [],
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
    by_file: list[list[dict]] = []
    read_failed = 0
    for path in list(dict.fromkeys(filenames))[:MAX_FILES]:
        try:
            verified_path = checked_config_path(path)
            cmd = remote_config_read_command(verified_path)
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
            base["config_files_read"] += 1
            try:
                config = load_config(raw.decode("utf-8-sig"), path)
            except (UnicodeError, ValueError, TypeError):
                # Syntax/encoding is invalid or unsupported; never echo
                # parser exceptions (they can include secret config bytes).
                base["config_files_parse_failed"] += 1
                continue
            base["config_files_checked"] += 1
            # Preserve the exact verified source file and structural setting
            # key; only selected endpoint facts leave the trusted worker.
            by_file.append([
                {**item, "config_file": verified_path}
                for item in discover(config)[:MAX_CHECKS]
            ])
        except Exception:
            # No parser trace or input excerpts: they can contain credentials.
            read_failed += 1
    base["config_files_failed"] = read_failed
    # Spread the fixed probe budget across verified files. Otherwise one
    # config with six endpoints can starve the failing dependency in another.
    known: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for index in range(MAX_CHECKS):
        for group in by_file:
            if index >= len(group):
                continue
            item = group[index]
            identity = (item["kind"], item["host"], item["port"])
            if identity not in seen:
                seen.add(identity)
                known.append(item)
            if len(known) >= MAX_CHECKS:
                break
        if len(known) >= MAX_CHECKS:
            break
    if not known:
        base["status"] = ("dependency_not_discovered" if base["config_files_checked"]
                          else "config_parse_failed" if base["config_files_parse_failed"]
                          else "config_read_unavailable")
        base["limitations"] = ["no_static_dependency_endpoint_verified"]
        return base
    followups: list[str] = []
    saw_unreachable = False
    saw_protocol_response = False
    for dependency in known:
        record = dict(dependency)
        try:
            if record["probe"] == "http_head":
                # Only the configured origin is probed. We do not send tokens,
                # URI paths or parameters to the destination or the LLM.
                record["probe_scope"] = "origin_root_head"
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
                record["probe_scope"] = "transport_tcp_connect"
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
                if record["tcp_reachable"] is False:
                    saw_unreachable = True
                    # The consumer VM is the right vantage point. Only a
                    # config-verified endpoint, never an LLM-selected host,
                    # is passed to bounded DNS and routing tools.
                    try:
                        dns = await connector.dns_check(target, record["host"])
                        record["dns_resolved"] = (
                            dns.get("resolved") if dns.get("success") is True
                            and type(dns.get("resolved")) is bool else None
                        )
                    except Exception:
                        record["dns_resolved"] = None
                    if record["dns_resolved"] is False:
                        if "review_dns_configuration" not in followups:
                            followups.append("review_dns_configuration")
                    else:
                        try:
                            route = await connector.route_check(target, record["host"])
                            record["route_found"] = (
                                route.get("route_found") if route.get("success") is True
                                and type(route.get("route_found")) is bool else None
                            )
                        except Exception:
                            record["route_found"] = None
                        if "review_network_path" not in followups:
                            followups.append("review_network_path")
                elif record["tcp_reachable"] is True and record["kind"] == "redis":
                    protocol = await redis_unauthenticated_ping(
                        connector, target, record["host"], record["port"],
                        tls=record.get("tls_requested") is True,
                    )
                    record.update(protocol)
                    if protocol["protocol_status"] in {
                        "authentication_required", "access_denied",
                    }:
                        saw_protocol_response = True
                        if "compare_application_auth_settings" not in followups:
                            followups.append("compare_application_auth_settings")
                    elif protocol["protocol_status"] == "unauthenticated_ping_ok":
                        saw_protocol_response = True
                        if "inspect_client_timeouts_pool_and_errors" not in followups:
                            followups.append("inspect_client_timeouts_pool_and_errors")
                    elif protocol["protocol_status"] == "tls_handshake_unverified":
                        if "review_tls_mode_and_certificates" not in followups:
                            followups.append("review_tls_mode_and_certificates")
                    else:
                        if "protocol_check_unavailable" not in followups:
                            followups.append("protocol_check_unavailable")
                elif record["tcp_reachable"] is True:
                    if "protocol_check_unavailable" not in followups:
                        followups.append("protocol_check_unavailable")
        except Exception:
            record["probe_supported"] = False
            record["probe_status"] = "check_unavailable"
        base["checks_executed"] += 1
        base["dependencies"].append(record)
    base["status"] = "checks_completed"
    base["next_checks"] = followups[:6]
    base["investigation_status"] = (
        "transport_failure_observed" if saw_unreachable else
        "redis_protocol_responded" if saw_protocol_response else
        "dependency_endpoint_checked"
    )
    base["protocol_health_verified"] = any(
        row.get("protocol_health_verified") is True
        for row in base["dependencies"]
    )
    # Even a PONG is not proof that the application's credentials, DB
    # selection, pool, timeouts or full business transactions are healthy.
    return base
