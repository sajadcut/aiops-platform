from typing import Any, Dict, Set

from domain.idempotency import request_fingerprint


class ExecutionIdempotency:
    _seen: Set[str] = set()

    @classmethod
    def key(cls, request: Dict[str, Any]) -> str:
        return request_fingerprint(request)

    @classmethod
    def already_seen(cls, request: Dict[str, Any]) -> bool:
        return cls.key(request) in cls._seen

    @classmethod
    def mark_seen(cls, request: Dict[str, Any]) -> None:
        cls._seen.add(cls.key(request))


def execution_fingerprint(payload: Dict[str, Any]) -> str:
    """Backward-compatible public fingerprint helper for execution callers/tests."""
    return request_fingerprint(payload)
