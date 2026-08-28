from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS_TOTAL = Counter(
    "aiops_http_requests_total",
    "HTTP requests processed by the control plane.",
    ("method", "route", "status"),
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "aiops_http_request_duration_seconds",
    "Control-plane HTTP request latency.",
    ("method", "route"),
)
HTTP_REQUESTS_IN_PROGRESS = Gauge(
    "aiops_http_requests_in_progress",
    "HTTP requests currently executing.",
)
DEPENDENCY_UP = Gauge(
    "aiops_dependency_up",
    "Dependency health as last observed by health/readiness probes.",
    ("dependency",),
)
DB_POOL_SIZE = Gauge("aiops_db_pool_size", "Configured/active SQLAlchemy pool size.")
DB_POOL_CHECKED_OUT = Gauge("aiops_db_pool_checked_out", "SQLAlchemy connections currently checked out.")
DB_POOL_OVERFLOW = Gauge("aiops_db_pool_overflow", "Current SQLAlchemy pool overflow count.")


def observe_http(method: str, route: str, status: int, duration_seconds: float) -> None:
    HTTP_REQUESTS_TOTAL.labels(method=method, route=route, status=str(status)).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=method, route=route).observe(duration_seconds)
