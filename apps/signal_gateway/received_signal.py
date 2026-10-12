"""Bounded redacted copy of the *received* external notification.

Only used as provenance for operator display. This data is never an execution
target, approval binding, search instruction or alternate source of truth.
"""
from __future__ import annotations

import json
from typing import Any

from domain.contracts.redaction import redact

MAX_RECEIVED_SIGNAL_BYTES = 65536


def capture_received_signal(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Retain JSON structure and source tag casing, not wire bytes/secret fields.

    Oversized payloads aren't falsely labelled exact: the durable normalized
    signal remains available as historical provenance instead.
    """
    if not isinstance(payload, dict):
        return None
    safe = redact(payload)
    try:
        encoded = json.dumps(safe, ensure_ascii=False, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return None
    if len(encoded.encode("utf-8")) > MAX_RECEIVED_SIGNAL_BYTES:
        return None
    return safe
