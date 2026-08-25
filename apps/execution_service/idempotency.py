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


def execution_fingerprint(*args: Any) -> str:
    """Create a deterministic fingerprint for execution callers.

    Supported contracts:
      execution_fingerprint(payload_dict)
      execution_fingerprint(action_or_tool, target, parameters)
      execution_fingerprint(tool_name, runbook_id, target, parameters)
    """
    if len(args) == 1 and isinstance(args[0], dict):
        payload = args[0]
    elif len(args) == 3:
        payload = {
            "action": args[0],
            "target": args[1],
            "parameters": args[2],
        }
    elif len(args) == 4:
        payload = {
            "tool_name": args[0],
            "runbook_id": args[1],
            "target": args[2],
            "parameters": args[3],
        }
    else:
        raise TypeError("execution_fingerprint expects 1, 3, or 4 arguments")
    return request_fingerprint(payload)
