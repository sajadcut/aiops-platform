"""Extract static Redis network endpoints from a trusted worker's .NET JSON file.

The raw configuration/connection string NEVER leaves the worker. This parser
only accepts a static, explicitly Redis-associated host:port; rejects variable
substitution, secrets, command text, arbitrary configuration keys and >4 peers.
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit
from typing import Any

_HOST = re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
_ADDR = re.compile(r"^\[([0-9a-fA-F:]+)\]:(\d{1,5})$")
_PLAIN = re.compile(r"^([A-Za-z0-9.-]{1,253}):(\d{1,5})$")
_BLOCK = re.compile(r"\$|%|[{};\\'\" \t\n\r]|[<>()]")
_MAX_ENDPOINTS = 4


def _safe_host(host: Any) -> str | None:
    value = str(host or "").strip().lower().rstrip(".")
    if len(value) > 253 or not value or _BLOCK.search(value):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value if _HOST.fullmatch(value) else None


def _port(value: Any) -> int | None:
    try:
        if isinstance(value, bool):
            return None
        n = int(value)
        return n if 1 <= n <= 65535 else None
    except (ValueError, TypeError):
        return None


def parse_redis_endpoints(value: Any) -> list[dict]:
    """Extract only network host/port, with no password, user or URL output."""
    endpoints: list[dict] = []
    seen = set()

    def add(host: Any, port: Any = None) -> None:
        clean = _safe_host(host)
        number = _port(port)
        if clean and (clean, number) not in seen and len(endpoints) < _MAX_ENDPOINTS:
            seen.add((clean, number))
            if number is None:
                endpoints.append({
                    "host": clean, "port": None, "port_inferred": True,
                })
            else:
                endpoints.append({"host": clean, "port": number})

    def parse_string(raw: str) -> None:
        text = raw.strip()
        if not text or len(text) > 1600:
            return
        if text.lower().startswith(("redis://", "rediss://")):
            try:
                uri = urlsplit(text)
                add(uri.hostname, uri.port)
            except ValueError:
                return
            return
        # StackExchange.Redis accepts "host:port,ssl=true,password=..."
        # Multiple endpoints can precede options. Never echo those options.
        for piece in text.split(",")[:8]:
            part = piece.strip()
            if _BLOCK.search(part):
                continue
            match = _PLAIN.fullmatch(part) or _ADDR.fullmatch(part)
            if match:
                add(match.group(1), match.group(2))
            elif _safe_host(part) and "=" not in part:
                add(part)

    def walk(node: Any, redis_scope: bool = False, depth: int = 0,
             inherited_port: int | None = None) -> None:
        if depth > 6 or len(endpoints) >= _MAX_ENDPOINTS:
            return
        if isinstance(node, dict):
            scoped = redis_scope
            # Preserve parent-level Redis.Port when Endpoints.Host is nested.
            local_port = _port(node.get("Port") or node.get("port")) or inherited_port
            if scoped:
                host = node.get("Host") or node.get("host") or node.get("Hostname") or node.get("hostname")
                if host is not None:
                    add(host, local_port)
            for k, v in list(node.items())[:75]:
                key = str(k).lower().replace("_", "").replace("-", "")
                key_redis = "redis" in key
                if key_redis:
                    walk(v, True, depth + 1, local_port)
                elif key in {"configuration", "connectionstring", "connectionstrings",
                             "endpoint", "endpoints", "servers", "nodes", "primary",
                             "cache"}:
                    # ConnectionStrings is not itself a Redis hint. Only a
                    # nested Redis key can enter the Redis parsing scope.
                    # assumes a random SQL/TCP connection string means Redis.
                    walk(v, scoped, depth + 1, local_port)
        elif isinstance(node, list):
            for entry in node[:8]:
                walk(entry, redis_scope, depth + 1, inherited_port)
        elif isinstance(node, str) and redis_scope:
            parse_string(node)

    if isinstance(value, (dict, list)):
        walk(value)
    elif isinstance(value, str):
        try:
            document = json.loads(value)
        except (ValueError, TypeError):
            return []
        walk(document)
    return endpoints


async def check_redis_config(connector: Any, target: str, service: str) -> dict:
    """Systemd-bound read-only Redis TCP diagnostics; never return config values.

    The MCP worker may temporarily read a bounded config over trusted SSH.
    LLM text cannot supply a path/host/port or turn this into an arbitrary
    network scanner. Static Redis host:port values are the only allowed peers.
    """
    import base64
    from integrations.vm.general_config_review import (
        checked_config_path, remote_config_read_command,
    )
    from integrations.vm.dotnet_local_validator import normalize_dotnet_json
    connector._validate_service(service)
    discovered = await connector.service_config_discovery(target, service)
    base = {
        "success": discovered.get("success") is True,
        "target": target, "service": service, "diagnostic": "redis_dependency_check",
        "status": "not_verified", "read_only": True,
        "execution_authority": False, "application_health_verified": False,
        "root_cause_confirmed": False, "config_contents_exposed": False,
        "secrets_exposed": False, "endpoints": [], "checked_files": 0,
    }
    if not discovered.get("success"):
        return {**base, "status": "config_discovery_unavailable"}
    files = [
        x.get("path") for x in (discovered.get("files") or [])[:16]
        if isinstance(x, dict) and x.get("verified_exists") is True
        and isinstance(x.get("path"), str)
        and (x["path"].rsplit("/", 1)[-1] == "appsettings.json"
             or (x["path"].rsplit("/", 1)[-1].startswith("appsettings.")
                 and x["path"].endswith(".json")))
    ]
    # Do not guess or read an unverified publish path: service_config_discovery
    # must prove the exact file before the worker can inspect its contents.
    if not files:
        return {**base, "status": "no_systemd_bound_appsettings"}
    found: list[dict] = []
    failures = 0
    for path in list(dict.fromkeys(files))[:3]:
        try:
            command = remote_config_read_command(checked_config_path(path))
            result = await connector._run(target, command)
            if not result.get("success"):
                failures += 1
                continue
            encoded = str(result.get("stdout") or "").strip()
            if not (1 <= len(encoded) <= 349528):
                failures += 1
                continue
            binary = base64.b64decode(encoded, validate=True)
            if not (1 <= len(binary) <= 262_144):
                failures += 1
                continue
            source = binary.decode("utf-8-sig")
            normalized = normalize_dotnet_json(source)
            config = json.loads(normalized)
            base["checked_files"] += 1
            for endpoint in parse_redis_endpoints(config):
                if endpoint not in found and len(found) < _MAX_ENDPOINTS:
                    found.append(endpoint)
        except Exception:
            failures += 1
            # No exception strings: parsers may include JSON config fragments.
    if not found:
        return {**base, "status": (
            "redis_endpoint_not_found" if base["checked_files"] else
            "config_read_or_parse_unavailable"),
            "file_failures": failures}
    for endpoint in found:
        entry = dict(endpoint)
        if entry.get("port") is None or entry.get("port_inferred") is True:
            entry.update({"tcp_supported": False, "tcp_reachable": None,
                          "tcp_status": "port_unverified"})
            base["endpoints"].append(entry)
            continue
        try:
            reach = await connector.tcp_check(target, entry["host"], entry["port"])
            entry["tcp_supported"] = (reach.get("success") is True and
                                       reach.get("supported") is True)
            entry["tcp_reachable"] = reach.get("reachable") if entry["tcp_supported"] else None
            entry["tcp_status"] = (
                "reachable" if entry["tcp_reachable"] is True else
                "unreachable" if entry["tcp_reachable"] is False else "unverified")
        except Exception:
            entry.update({"tcp_supported": False, "tcp_reachable": None,
                          "tcp_status": "check_unavailable"})
        base["endpoints"].append(entry)
    base["status"] = "tcp_checked" if any(x.get("tcp_supported") for x in base["endpoints"]) else "tcp_unverified"
    return base
