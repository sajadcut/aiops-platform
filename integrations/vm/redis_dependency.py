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

    def add(host: Any, port: Any = 6379) -> None:
        clean = _safe_host(host)
        number = _port(port)
        if clean and number and (clean, number) not in seen and len(endpoints) < _MAX_ENDPOINTS:
            seen.add((clean, number))
            endpoints.append({"host": clean, "port": number})

    def parse_string(raw: str) -> None:
        text = raw.strip()
        if not text or len(text) > 1600:
            return
        if text.lower().startswith(("redis://", "rediss://")):
            try:
                uri = urlsplit(text)
                add(uri.hostname, uri.port or 6379)
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

    def walk(node: Any, redis_scope: bool = False, depth: int = 0) -> None:
        if depth > 6 or len(endpoints) >= _MAX_ENDPOINTS:
            return
        if isinstance(node, dict):
            scoped = redis_scope
            if scoped:
                host = node.get("Host") or node.get("host") or node.get("Hostname") or node.get("hostname")
                if host is not None:
                    add(host, node.get("Port") or node.get("port") or 6379)
            for k, v in list(node.items())[:75]:
                key = str(k).lower().replace("_", "").replace("-", "")
                key_redis = "redis" in key
                if key_redis:
                    walk(v, True, depth + 1)
                elif key in {"configuration", "connectionstring", "connectionstrings",
                             "endpoint", "endpoints", "servers", "nodes", "primary",
                             "host", "hostname", "address", "cache"}:
                    # connectionstrings only contains Redis keys, and never
                    # assumes a random SQL/TCP connection string means Redis.
                    walk(v, scoped or key == "cache", depth + 1)
        elif isinstance(node, list):
            for entry in node[:8]:
                walk(entry, redis_scope, depth + 1)
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
