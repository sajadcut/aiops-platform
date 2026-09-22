from __future__ import annotations

import secrets
from threading import Lock
from time import monotonic

from domain.contracts.config import settings


_LOCK = Lock()
_ISSUED: dict[str, float] = {}


def _ttl_seconds() -> float:
    # Approval TTL is the outer authority lifetime; the in-process handoff is
    # intentionally much shorter to prevent abandoned claims accumulating.
    configured = float(getattr(settings, "APPROVAL_TTL_SECONDS", 900) or 900)
    return max(5.0, min(configured, 60.0))


def _purge_expired(now: float) -> None:
    expired = [token for token, expires_at in _ISSUED.items() if expires_at <= now]
    for token in expired:
        _ISSUED.pop(token, None)


def issue_execution_claim() -> str:
    """Mint one process-local, single-use execution capability.

    The claim exists only between the successful PostgreSQL approval consume
    compare-and-set and the immediate internal execution boundary. It is never
    persisted, so reloading a consumed approval cannot recreate authority.
    """
    token = secrets.token_urlsafe(32)
    now = monotonic()
    with _LOCK:
        _purge_expired(now)
        _ISSUED[token] = now + _ttl_seconds()
    return token


def redeem_execution_claim(token: str) -> bool:
    """Atomically redeem a claim exactly once."""
    value = str(token or "").strip()
    if not value:
        return False
    now = monotonic()
    with _LOCK:
        _purge_expired(now)
        expires_at = _ISSUED.pop(value, None)
        return bool(expires_at is not None and expires_at > now)
