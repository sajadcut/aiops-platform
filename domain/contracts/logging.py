from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Any

import structlog

from domain.contracts.config import settings

_REDACTED = "[REDACTED]"
_SENSITIVE_EXACT_KEYS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x_api_key",
    "api_key",
    "apikey",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "private_key",
    "private_key_data",
    "ssh_credential",
    "ssh_password",
    "database_url",
    "alembic_database_url",
}
_SENSITIVE_SUFFIXES = ("_token", "_password", "_secret", "_api_key", "_private_key")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIAL_RE = re.compile(r"(?i)(\b(?:postgresql|postgres|mysql|mariadb|redis|amqp)(?:\+[a-z0-9_]+)?://[^:\s/@]+:)([^@\s/]+)(@)")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL)


def _sensitive_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace(" ", "_")
    return normalized in _SENSITIVE_EXACT_KEYS or normalized.endswith(_SENSITIVE_SUFFIXES)


def redact_value(value: Any, *, key: Any = None) -> Any:
    """Recursively redact known secret-bearing keys and credential-shaped strings."""
    if key is not None and _sensitive_key(key):
        return _REDACTED
    if isinstance(value, dict):
        return {str(k): redact_value(v, key=k) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        sanitized = _BEARER_RE.sub("Bearer [REDACTED]", value)
        sanitized = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]\3", sanitized)
        sanitized = _PRIVATE_KEY_RE.sub(_REDACTED, sanitized)
        return sanitized
    return value


def _redact_processor(_logger, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    return redact_value(event_dict)


def _processor_formatter(renderer):
    foreign_pre_chain = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=settings.LOG_UTC),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact_processor,
    ]
    return structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=foreign_pre_chain,
    )


def _file_handler(path: Path) -> logging.Handler:
    path.parent.mkdir(parents=True, exist_ok=True)
    if settings.LOG_ROTATION_MODE.lower() == "time":
        return TimedRotatingFileHandler(
            path,
            when=settings.LOG_ROTATION_WHEN,
            interval=settings.LOG_ROTATION_INTERVAL,
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding="utf-8",
            utc=settings.LOG_UTC,
        )
    return RotatingFileHandler(
        path,
        maxBytes=settings.LOG_MAX_BYTES,
        backupCount=settings.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )


def configure_logging() -> None:
    """Configure redacted human-readable and structured JSON logging sinks."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso", utc=settings.LOG_UTC),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            _redact_processor,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    human_formatter = _processor_formatter(structlog.dev.ConsoleRenderer(colors=False))
    json_formatter = _processor_formatter(structlog.processors.JSONRenderer(sort_keys=True))

    handlers: list[logging.Handler] = []
    if settings.LOG_CONSOLE_ENABLED:
        console = logging.StreamHandler()
        console.setFormatter(human_formatter)
        handlers.append(console)

    log_dir = Path(settings.LOG_DIR).expanduser()
    if settings.LOG_TEXT_FILE_ENABLED:
        text_handler = _file_handler(log_dir / settings.LOG_TEXT_FILE)
        text_handler.setFormatter(human_formatter)
        handlers.append(text_handler)

    if settings.LOG_JSON_FILE_ENABLED:
        json_handler = _file_handler(log_dir / settings.LOG_JSON_FILE)
        json_handler.setFormatter(json_formatter)
        handlers.append(json_handler)

    if not handlers:
        raise RuntimeError("logging_configuration_invalid:no_log_destination_enabled")

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(log_level)
    for handler in handlers:
        handler.setLevel(log_level)
        root_logger.addHandler(handler)

    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.setLevel(log_level)
        uvicorn_logger.propagate = True


logger = structlog.get_logger("aiops")
