"""Request-scoped Kubernetes identity from an authenticated Zabbix webhook.

An event's explicit namespace is used only for read-only MCP evidence lookups.
It is not an authorization grant for workload mutations.
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Optional

_CURRENT_NAMESPACE: ContextVar[Optional[str]] = ContextVar(
    "aiops_current_kubernetes_namespace", default=None
)


def bind_kubernetes_namespace(namespace: Optional[str]) -> Token:
    value = str(namespace or "").strip()
    return _CURRENT_NAMESPACE.set(value or None)


def current_kubernetes_namespace() -> Optional[str]:
    return _CURRENT_NAMESPACE.get()


def reset_kubernetes_namespace(token: Token) -> None:
    _CURRENT_NAMESPACE.reset(token)
