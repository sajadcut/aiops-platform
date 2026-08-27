"""ساخت fingerprint پایدار برای تشخیص execution تکراری.

هدف idempotency این است که retry، double-click یا resume workflow یک action را دوباره با
همان target/parameters اجرا نکند. این کلاس cache process-local ساده‌ای دارد؛ durability
اصلی execution باید همچنان از checkpoint/persistence و approval consume پشتیبانی شود.
"""

from typing import Any, Dict, Set

from domain.idempotency import request_fingerprint


class ExecutionIdempotency:
    """Registry درون-process از fingerprintهای دیده‌شده برای جلوگیری از duplicate سریع."""

    _seen: Set[str] = set()

    @classmethod
    def key(cls, request: Dict[str, Any]) -> str:
        """Request را با canonical hashing دامنه به یک کلید deterministic تبدیل می‌کند."""
        return request_fingerprint(request)

    @classmethod
    def already_seen(cls, request: Dict[str, Any]) -> bool:
        """بررسی می‌کند همین request در عمر process فعلی قبلاً علامت‌گذاری شده یا نه."""
        return cls.key(request) in cls._seen

    @classmethod
    def mark_seen(cls, request: Dict[str, Any]) -> None:
        """بعد از پذیرش execution fingerprint را ثبت می‌کند تا retry فوری duplicate نشود."""
        cls._seen.add(cls.key(request))


def execution_fingerprint(*args: Any) -> str:
    """چند contract قدیمی/جدید caller را به یک payload canonical و fingerprint واحد تبدیل می‌کند."""
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
