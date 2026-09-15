from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Dict, Optional


_CURRENT_VM_TARGET: ContextVar[Optional[str]] = ContextVar(
    "aiops_current_vm_target",
    default=None,
)


def _clean(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def target_from_zabbix_payload(payload: Dict[str, Any]) -> Optional[str]:
    """Resolve the VM endpoint without conflating it with the service name.

    Zabbix signal payloads may already contain a normalized target_ip. Prefer
    that authoritative endpoint, then interface/ip fields, then the host name.
    Service/application labels are intentionally never considered VM targets.
    """
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


def bind_vm_target(target: Optional[str]) -> Token:
    return _CURRENT_VM_TARGET.set(_clean(target))


def reset_vm_target(token: Token) -> None:
    _CURRENT_VM_TARGET.reset(token)


def current_vm_target() -> Optional[str]:
    return _clean(_CURRENT_VM_TARGET.get())
