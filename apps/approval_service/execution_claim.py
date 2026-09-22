from __future__ import annotations

import secrets
from threading import Lock


_LOCK = Lock()
_ISSUED: set[str] = set()


def issue_execution_claim() -> str:
    """Mint one process-local single-use execution capability.

    The claim is deliberately not persisted. It exists only between the
    successful PostgreSQL approval consume CAS and the immediate internal
    execution boundary. A consumed approval loaded later from PostgreSQL cannot
    recreate this capability.
    """
    token = secrets.token_urlsafe(32)
    with _LOCK:
        _ISSUED.add(token)
    return token


def redeem_execution_claim(token: str) -> bool:
    """Atomically redeem a previously issued claim exactly once."""
    value = str(token or "").strip()
    if not value:
        return False
    with _LOCK:
        if value not in _ISSUED:
            return False
        _ISSUED.remove(value)
        return True
