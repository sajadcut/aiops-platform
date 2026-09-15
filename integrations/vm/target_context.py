from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Dict, Optional


_CURRENT_VM_TARGET: ContextVar[Optional[str]] = ContextVar(
    "aiops_current_vm_target",
    default=None,
)
_CURRENT_VM_PORT: ContextVar[Optional[int]] = ContextVar(
    "aiops_current_vm_port",
    default=None,
)


def _clean(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def target_from_zabbix_payload(payload: Dict[str, Any]) -> Optional[str]:
    """Resolve a VM endpoint without conflating it with the service name."""
    for key in ("target_ip", "interface_ip", "ip"):
        value = _clean(payload.get(key))
        if value:
            return value

    host = payload.get("host")
    if isinstance(host, dict):
        for key in ("target_ip", "interface_ip", "ip"):
            value = _clean(host.get(key))
            if value:
                return value
        interfaces = host.get("interfaces") or []
        if isinstance(interfaces, list):
            for interface in interfaces:
                if not isinstance(interface, dict):
                    continue
                value = _clean(interface.get("ip"))
                if value:
                    return value
        for key in ("host", "name", "hostname"):
            value = _clean(host.get(key))
            if value:
                return value

    return _clean(payload.get("hostname")) or _clean(host)


def target_port_from_zabbix_payload(payload: Dict[str, Any]) -> Optional[int]:
    """Return only an explicitly supplied TCP target port.

    Parsing a port from free-form trigger text would make the execution target
    dependent on untrusted prose. The webhook's normalized ``target_port`` is
    therefore the authoritative source.
    """
    raw = payload.get("target_port")
    if raw in (None, ""):
        return None
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def bind_vm_target(target: Optional[str]) -> Token:
    return _CURRENT_VM_TARGET.set(_clean(target))


def reset_vm_target(token: Token) -> None:
    _CURRENT_VM_TARGET.reset(token)


def current_vm_target() -> Optional[str]:
    return _clean(_CURRENT_VM_TARGET.get())


def bind_vm_port(port: Optional[int]) -> Token:
    return _CURRENT_VM_PORT.set(port if port is not None and 1 <= int(port) <= 65535 else None)


def reset_vm_port(token: Token) -> None:
    _CURRENT_VM_PORT.reset(token)


def current_vm_port() -> Optional[int]:
    value = _CURRENT_VM_PORT.get()
    return int(value) if value is not None else None
