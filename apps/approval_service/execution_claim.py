from __future__ import annotations

import secrets
from threading import Lock


_LOCK = Lock()
_ISSUED: set[str] = set()


def issue_execution_claim() -> str:
    """Mint one process-local, single-use execution capability.

    The claim exists only between the successful PostgreSQL approval consume
    compare-and-set and the immediate internal execution boundary. It is never
    persisted, so reloading a consumed approval cannot recreate authority.
    """
    token = secrets.token_urlsafe(32)
    with _LOCK:
        _ISSUED.add(token)
    return token


def redeem_execution_claim(token: str) -> bool:
    """Atomically redeem a claim exactly once."""
    value = str(token or "").strip()
    if not value:
        return False
    with _LOCK:
        if value not in _ISSUED:
            return False
        _ISSUED.remove(value)
        return True
