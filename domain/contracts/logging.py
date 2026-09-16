from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

from domain.contracts.config import settings
from domain.contracts.context import (
    bind_incident_context,
    get_incident_id,
    get_rid,
    get_trace_id,
    incident_rid,
)
from domain.contracts.redaction import redact_event_dict

_CORRELATION_KEYS = ("rid", "correlation_id", "trace_id")


def _correlation_context_processor(_logger, _method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Attach request trace + stable Incident RID to every log event.

    Explicit ``incident_id`` values become the current async task's Incident
    context. This makes later stdlib/structlog events automatically traceable
    even when individual log calls do not repeat the Incident id.
    """
    explicit_incident = event_dict.get("incident_id")
    if explicit_incident not in (None, ""):
        incident_id = str(explicit_incident)
        event_dict["incident_id"] = incident_id
        event_dict.setdefault("rid", bind_incident_context(incident_id))
    else:
        incident_id = get_incident_id()
        if incident_id:
            event_dict.setdefault("incident_id", incident_id)
        rid = get_rid()
        if rid:
            event_dict.setdefault("rid", rid)

    trace_id = get_trace_id()
    if trace_id:
        event_dict.setdefault("trace_id", trace_id)
    return event_dict


def _correlation_first_fields(_logger, _method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Keep correlation identifiers immediately after log level in serialized logs."""
    ordered: Dict[str, Any] = {}
    for key in ("timestamp", "level", *_CORRELATION_KEYS, "event", "logger"):
        if key in event_dict:
            ordered[key] = event_dict[key]
    for key, value in event_dict.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def _inline_correlation_value(value: Any) -> str:
    """Render one correlation value without allowing it to break the log line."""
    return str(value).replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


def _human_console_renderer():
    """Render correlation identifiers directly after ``[level]`` in text logs."""
    base_renderer = structlog.dev.ConsoleRenderer(colors=False, sort_keys=False)

    def render(logger, method_name: str, event_dict: Dict[str, Any]) -> str:
        payload = dict(event_dict)
        correlation_parts = []
        for key in _CORRELATION_KEYS:
            value = payload.pop(key, None)
            if value not in (None, ""):
                correlation_parts.append(f"{key}={_inline_correlation_value(value)}")
        if correlation_parts:
            event = str(payload.get("event") or "")
            payload["event"] = f"{' '.join(correlation_parts)} {event}".strip()
        return base_renderer(logger, method_name, payload)

    return render


def _processor_formatter(renderer):
    foreign_pre_chain = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        _correlation_context_processor,
        structlog.processors.TimeStamper(fmt="iso", utc=settings.LOG_UTC),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_event_dict,
        _correlation_first_fields,
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
    """Configure human console/text logs and JSON-line file logs.

    Every event passes through the same recursive redaction and correlation
    processors, including traceback text from stdlib/FastAPI/Uvicorn loggers.
    Canonical Incident events carry a stable ``rid`` so one Incident can be
    traced across request, agent, MCP, approval, execution and verification
    logs without adding a database column. Correlation identifiers are rendered
    immediately after the log level for fast operator scanning.
    """
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.PositionalArgumentsFormatter(),
            _correlation_context_processor,
            structlog.processors.TimeStamper(fmt="iso", utc=settings.LOG_UTC),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            redact_event_dict,
            structlog.processors.UnicodeDecoder(),
            _correlation_first_fields,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    human_formatter = _processor_formatter(_human_console_renderer())
    json_formatter = _processor_formatter(structlog.processors.JSONRenderer(sort_keys=False))

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

    # Route Uvicorn/FastAPI stdlib logs through the same file/JSON/redaction path.
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.setLevel(log_level)
        uvicorn_logger.propagate = True


logger = structlog.get_logger("aiops")


def log_workflow_step(
    *,
    incident_id: Optional[str],
    stage: str,
    component: str,
    action: str,
    status: str = "completed",
    summary: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    level: str = "info",
) -> None:
    """Emit one canonical Incident timeline event to text and JSON logs.

    Supplying ``incident_id`` also binds that Incident to the current asyncio
    context. Subsequent log calls in the same task inherit ``incident_id`` and
    ``rid`` automatically until another Incident is bound or the request
    middleware clears the context.
    """
    stage_name = str(stage or "unknown").strip() or "unknown"
    component_name = str(component or "unknown").strip() or "unknown"
    action_name = str(action or "unknown").strip() or "unknown"
    status_name = str(status or "unknown").strip().lower() or "unknown"
    normalized_incident_id = str(incident_id) if incident_id else None
    payload: Dict[str, Any] = {
        "log_type": "incident_timeline",
        "incident_id": normalized_incident_id,
        "rid": incident_rid(normalized_incident_id) if normalized_incident_id else None,
        "stage": stage_name,
        "component": component_name,
        "action": action_name,
        "status": status_name,
    }
    if summary:
        payload["summary"] = str(summary)[:1000]
    if details:
        payload["details"] = details

    level_name = str(level or "info").strip().lower()
    log_method = getattr(logger, level_name, logger.info)
    log_method("workflow_step", **payload)
