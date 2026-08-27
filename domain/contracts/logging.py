from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path

import structlog

from domain.contracts.config import settings


def _processor_formatter(renderer):
    foreign_pre_chain = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=settings.LOG_UTC),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
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
    """Configure human-readable console/text logs and JSON-line file logs.

    Runtime values come exclusively from the canonical `.env`.  The same event
    may be emitted to three destinations: console (human), rotating text file
    (human), and rotating JSON-lines file (machine/SIEM ingestion).
    """
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

    # Route Uvicorn/FastAPI standard-library logs through the same handlers so
    # access/errors are persisted in both human and JSON formats as well.
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.setLevel(log_level)
        uvicorn_logger.propagate = True


logger = structlog.get_logger("aiops")
