from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any, List, Optional

from domain.contracts.config import settings
from integrations.base import Alert, MetricPoint
from integrations.mcp_client import MCPClient


class PrometheusMCPClient(MCPClient):
    """Adapter for the official prometheus/prometheus-mcp read-only contract."""

    _LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
    _SAMPLE_RE = re.compile(
        r"^\s*(NaN|[+-]?Inf|[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s+@\[(.+?)\]\s*$"
    )

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(
            server_url or settings.PROMETHEUS_MCP_URL,
            "prometheus",
            allowed_tools={
                "query",
                "range_query",
                "list_alerts",
                "metric_metadata",
                "series",
                "label_names",
                "label_values",
                "healthy",
                "ready",
            },
            protocol_version=settings.PROMETHEUS_MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            # The official server forwards an inbound Authorization header to
            # Prometheus. Never leak the generic Control-Plane MCP bearer into
            # that backend implicitly; use PROMETHEUS_MCP_AUTH_HEADER only when
            # an explicit passthrough credential is intentionally required.
            bearer_token=None,
            authorization_header=settings.PROMETHEUS_MCP_AUTH_HEADER,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
        )

    @staticmethod
    def _dt(value: object) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except (ValueError, TypeError, OSError):
                return datetime.now(timezone.utc)
        text = str(value).strip()
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            pass
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _payloads(result: dict) -> list[Any]:
        """Decode ordinary JSON tool outputs while preserving query text wrappers."""
        payloads = MCPClient.json_content(result)
        expanded: list[Any] = []
        for payload in payloads:
            if isinstance(payload, dict) and isinstance(payload.get("result"), str):
                try:
                    value = json.loads(payload["result"])
                except json.JSONDecodeError:
                    # Official query/range_query output is Prometheus model text
                    # inside the JSON "result" field, not raw Prometheus API JSON.
                    expanded.append(payload)
                else:
                    expanded.extend(value if isinstance(value, list) else [value])
            else:
                expanded.append(payload)
        return expanded

    @staticmethod
    def _selector(metric: str, service: str) -> str:
        label = settings.PROMETHEUS_MCP_SERVICE_LABEL.strip() or "service"
        escaped = service.replace("\\", "\\\\").replace('"', '\\"')
        return f'{metric}{{{label}="{escaped}"}}'

    @classmethod
    def _parse_metric_header(cls, header: str) -> dict[str, str]:
        header = str(header or "").strip()
        labels: dict[str, str] = {}

        brace_index = header.find("{")
        if brace_index >= 0:
            metric_name = header[:brace_index].strip()
        else:
            metric_name = header if header not in {"", "{}"} else ""

        if metric_name:
            labels["__name__"] = metric_name

        for match in cls._LABEL_RE.finditer(header):
            key, raw_value = match.groups()
            try:
                value = json.loads(f'"{raw_value}"')
            except json.JSONDecodeError:
                value = raw_value
            labels[str(key)] = str(value)
        return labels

    @classmethod
    def _points_from_official_query_text(
        cls,
        text: str,
        *,
        fallback_metric: str,
        fallback_service: str,
    ) -> list[MetricPoint]:
        """Parse prometheus/common Matrix.String() emitted by range_query.

        Example:
            http_requests_total{service="payments"} =>
            1.5 @[1756143048]
            2 @[1756143063]
        """
        points: list[MetricPoint] = []
        current_labels: dict[str, str] = {}
        service_label = settings.PROMETHEUS_MCP_SERVICE_LABEL.strip() or "service"

        def append_sample(sample_text: str) -> None:
            match = cls._SAMPLE_RE.match(sample_text)
            if not match:
                return
            raw_value, raw_timestamp = match.groups()
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                return
            if not math.isfinite(value):
                return

            labels = dict(current_labels)
            service_value = (
                labels.get(service_label)
                or labels.get("service")
                or labels.get("job")
                or fallback_service
            )
            metric_name = labels.get("__name__") or fallback_metric
            points.append(
                MetricPoint(
                    timestamp=cls._dt(raw_timestamp),
                    service=str(service_value),
                    name=str(metric_name),
                    value=value,
                    labels=labels,
                    source="prometheus",
                )
            )

        for raw_line in str(text or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "=>" in line:
                header, sample = line.split("=>", 1)
                current_labels = cls._parse_metric_header(header)
                if sample.strip():
                    append_sample(sample.strip())
                continue
            append_sample(line)

        return points

    @classmethod
    def _points_from_payload(
        cls,
        payload: Any,
        *,
        fallback_metric: str,
        fallback_service: str,
    ) -> list[MetricPoint]:
        if not isinstance(payload, dict):
            return []

        result_text = payload.get("result")
        if isinstance(result_text, str):
            try:
                decoded = json.loads(result_text)
            except json.JSONDecodeError:
                return cls._points_from_official_query_text(
                    result_text,
                    fallback_metric=fallback_metric,
                    fallback_service=fallback_service,
                )
            candidates = decoded if isinstance(decoded, list) else [decoded]
            points: list[MetricPoint] = []
            for candidate in candidates:
                points.extend(
                    cls._points_from_payload(
                        candidate,
                        fallback_metric=fallback_metric,
                        fallback_service=fallback_service,
                    )
                )
            return points

        metric = payload.get("metric") or {}
        values = payload.get("values") or []
        if not values and payload.get("value"):
            values = [payload.get("value")]
        if not isinstance(metric, dict) or not isinstance(values, list):
            return []

        labels = {str(k): str(v) for k, v in metric.items()}
        service_label = settings.PROMETHEUS_MCP_SERVICE_LABEL.strip() or "service"
        service_value = (
            labels.get(service_label)
            or labels.get("service")
            or labels.get("job")
            or fallback_service
        )
        metric_name = labels.get("__name__") or fallback_metric
        points: list[MetricPoint] = []
        for sample in values[-50:]:
            if not isinstance(sample, (list, tuple)) or len(sample) < 2:
                continue
            try:
                value = float(sample[1])
            except (TypeError, ValueError):
                continue
            if not math.isfinite(value):
                continue
            points.append(
                MetricPoint(
                    timestamp=cls._dt(sample[0]),
                    service=str(service_value),
                    name=str(metric_name),
                    value=value,
                    labels=labels,
                    source="prometheus",
                )
            )
        return points

    async def get_metrics(
        self,
        service: str,
        metric_names: List[str],
        since: datetime,
        until: Optional[datetime] = None,
    ) -> List[MetricPoint]:
        points: List[MetricPoint] = []
        end = until or datetime.now(timezone.utc)
        for metric_name in [str(x) for x in metric_names[:25]]:
            result = await self.call_tool(
                "range_query",
                {
                    "query": self._selector(metric_name, service),
                    "start_time": since.isoformat(),
                    "end_time": end.isoformat(),
                    "truncation_limit": 200,
                },
            )
            metric_points: list[MetricPoint] = []
            for payload in MCPClient.json_content(result):
                metric_points.extend(
                    self._points_from_payload(
                        payload,
                        fallback_metric=metric_name,
                        fallback_service=service,
                    )
                )
            points.extend(metric_points[-50:])
        return points

    async def get_alerts(
        self,
        since: Optional[datetime] = None,
        service: Optional[str] = None,
        limit: int = 100,
    ) -> List[Alert]:
        result = await self.call_tool("list_alerts", {})
        alerts: List[Alert] = []
        service_label = settings.PROMETHEUS_MCP_SERVICE_LABEL.strip() or "service"
        for payload in self._payloads(result):
            candidates = (
                payload.get("alerts", [])
                if isinstance(payload, dict) and isinstance(payload.get("alerts"), list)
                else [payload]
            )
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                labels = item.get("labels") or {}
                if not isinstance(labels, dict):
                    labels = {}
                service_value = labels.get(service_label) or labels.get("service") or labels.get("job")
                if service and service_value and str(service_value) != service:
                    continue
                active_at = item.get("activeAt") or item.get("active_at") or item.get("timestamp")
                timestamp = self._dt(active_at)
                if since and timestamp < since:
                    continue
                annotations = item.get("annotations") or {}
                if not isinstance(annotations, dict):
                    annotations = {}
                alerts.append(
                    Alert(
                        source="prometheus",
                        source_id=str(item.get("fingerprint") or labels.get("alertname") or len(alerts)),
                        severity=str(labels.get("severity") or item.get("severity") or "unknown"),
                        service=str(service_value or service or "unknown"),
                        message=str(
                            annotations.get("summary")
                            or annotations.get("description")
                            or labels.get("alertname")
                            or "Prometheus alert"
                        ),
                        timestamp=timestamp,
                        raw_data=item,
                    )
                )
                if len(alerts) >= min(max(int(limit), 1), 500):
                    return alerts
        return alerts

    async def health_check(self) -> bool:
        """Check the upstream Prometheus backend readiness through the official tool."""
        try:
            await self.call_tool("ready", {})
            return True
        except Exception:
            return False
