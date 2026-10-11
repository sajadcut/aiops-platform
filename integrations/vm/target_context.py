from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Dict, Optional

from integrations.zabbix.webhook_contract import clean_zabbix_value, zabbix_tags


_CURRENT_VM_TARGET: ContextVar[Optional[str]] = ContextVar(
    "aiops_current_vm_target",
    default=None,
)
_CURRENT_VM_PORT: ContextVar[Optional[int]] = ContextVar(
    "aiops_current_vm_port",
    default=None,
)
_BLOCK_VM_PROBES: ContextVar[bool] = ContextVar(
    "aiops_block_vm_probes_for_non_vm_signal", default=False
)


def bind_vm_probe_blocked(blocked: bool) -> Token:
    return _BLOCK_VM_PROBES.set(bool(blocked))


def reset_vm_probe_blocked(token: Token) -> None:
    _BLOCK_VM_PROBES.reset(token)


def vm_probes_blocked() -> bool:
    return bool(_BLOCK_VM_PROBES.get())


def _clean(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def target_from_zabbix_payload(payload: Dict[str, Any]) -> Optional[str]:
    """Only the explicit target_ip field/tag may select a VM MCP target.

    The v1.1 team guide explicitly forbids deriving an execution target from
    HOST.IP, HOST.HOST or free-form trigger/service text.
    """
    target = clean_zabbix_value(payload.get("target_ip"))
    if target:
        return target
    for item in zabbix_tags(payload.get("tags")):
        if item["tag"] == "target_ip" and item["value"]:
            return item["value"]
    return None


def target_port_from_zabbix_payload(payload: Dict[str, Any]) -> Optional[int]:
    """Only a valid explicit target_port field/tag is accepted."""
    value = clean_zabbix_value(payload.get("target_port"))
    if not value:
        for item in zabbix_tags(payload.get("tags")):
            if item["tag"] == "target_port":
                value = item["value"]
                break
    if not value.isascii() or not value.isdecimal():
        return None
    port = int(value)
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
