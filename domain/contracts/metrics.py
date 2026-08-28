from __future__ import annotations

from typing import Any

from prometheus_client import Counter, Gauge, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "aiops_http_requests_total",
    "HTTP requests completed by the API",
    ("method", "route", "status"),
)
HTTP_DURATION = Histogram(
    "aiops_http_request_duration_seconds",
    "HTTP request duration",
    ("method", "route"),
)
HTTP_IN_FLIGHT = Gauge(
    "aiops_http_requests_in_flight",
    "HTTP requests currently being processed",
)
EXECUTIONS = Counter(
    "aiops_executions_total",
    "Governed execution outcomes",
    ("tool", "action", "outcome"),
)
MCP_REQUESTS = Counter(
    "aiops_mcp_requests_total",
    "MCP request outcomes",
    ("provider", "method", "tool", "outcome"),
)
MCP_DURATION = Histogram(
    "aiops_mcp_request_duration_seconds",
    "MCP request duration",
    ("provider", "method", "tool"),
)
DB_POOL_SIZE = Gauge("aiops_db_pool_size", "Configured SQLAlchemy DB pool size")
DB_POOL_CHECKED_OUT = Gauge("aiops_db_pool_checked_out", "SQLAlchemy DB connections currently checked out")
DB_POOL_OVERFLOW = Gauge("aiops_db_pool_overflow", "SQLAlchemy DB pool overflow connections")


def observe_http(method: str, route: str, status: int, duration_seconds: float) -> None:
    safe_method = str(method or "UNKNOWN")[:16]
    safe_route = str(route or "unknown")[:200]
    HTTP_REQUESTS.labels(safe_method, safe_route, str(int(status))).inc()
    HTTP_DURATION.labels(safe_method, safe_route).observe(max(float(duration_seconds), 0.0))


def observe_execution(tool: str, action: str, outcome: str) -> None:
    EXECUTIONS.labels(str(tool)[:100], str(action)[:100], str(outcome)[:50]).inc()


def observe_mcp(provider: str, method: str, tool: str | None, outcome: str, duration_seconds: float) -> None:
    labels = (str(provider)[:100], str(method)[:100], str(tool or "-")[:100])
    MCP_REQUESTS.labels(*labels, str(outcome)[:50]).inc()
    MCP_DURATION.labels(*labels).observe(max(float(duration_seconds), 0.0))


def update_db_pool_metrics(engine: Any) -> None:
    pool = engine.sync_engine.pool
    for gauge, accessor in (
        (DB_POOL_SIZE, "size"),
        (DB_POOL_CHECKED_OUT, "checkedout"),
        (DB_POOL_OVERFLOW, "overflow"),
    ):
        method = getattr(pool, accessor, None)
        if callable(method):
            try:
                gauge.set(float(method()))
            except Exception:
                continue


def render_metrics() -> bytes:
    return generate_latest()
