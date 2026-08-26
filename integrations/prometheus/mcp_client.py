from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, List, Optional

from domain.contracts.config import settings
from integrations.base import Alert, MetricPoint
from integrations.mcp_client import MCPClient


class PrometheusMCPClient(MCPClient):
    """Adapter for prometheus/prometheus-mcp read-only tools."""

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(
            server_url or settings.PROMETHEUS_MCP_URL,
            "prometheus",
            allowed_tools={"query", "range_query", "list_alerts", "metric_metadata", "series", "label_names", "label_values", "healthy", "ready"},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            authorization_header=settings.PROMETHEUS_MCP_AUTH_HEADER,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )

    @staticmethod
    def _dt(value: object) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        try:
            if isinstance(value, (int, float)) or str(value).replace(".", "", 1).isdigit():
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError, OSError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _payloads(result: dict) -> list[Any]:
        payloads = MCPClient.json_content(result)
        expanded: list[Any] = []
        for payload in payloads:
            if isinstance(payload, dict) and isinstance(payload.get("result"), str):
                try:
                    value = json.loads(payload["result"])
                except json.JSONDecodeError:
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

    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        points: List[MetricPoint] = []
        end = until or datetime.now(timezone.utc)
        for metric_name in [str(x) for x in metric_names[:25]]:
            result = await self.call_tool("range_query", {
                "query": self._selector(metric_name, service),
                "start_time": since.isoformat(),
                "end_time": end.isoformat(),
                "truncation_limit": 200,
            })
            for payload in self._payloads(result):
                if not isinstance(payload, dict):
                    continue
                metric = payload.get("metric") or {}
                values = payload.get("values") or []
                if not values and payload.get("value"):
                    values = [payload.get("value")]
                for sample in values[-50:]:
                    if not isinstance(sample, (list, tuple)) or len(sample) < 2:
                        continue
                    try:
                        value = float(sample[1])
                    except (TypeError, ValueError):
                        continue
                    labels = {str(k): str(v) for k, v in metric.items()} if isinstance(metric, dict) else {}
                    points.append(MetricPoint(
                        timestamp=self._dt(sample[0]),
                        service=str(labels.get(settings.PROMETHEUS_MCP_SERVICE_LABEL) or service),
                        name=str(labels.get("__name__") or metric_name),
                        value=value,
                        labels=labels,
                        source="prometheus",
                    ))
        return points

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        result = await self.call_tool("list_alerts", {})
        alerts: List[Alert] = []
        for payload in self._payloads(result):
            candidates = payload.get("alerts", []) if isinstance(payload, dict) and isinstance(payload.get("alerts"), list) else [payload]
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                labels = item.get("labels") or {}
                service_value = labels.get(settings.PROMETHEUS_MCP_SERVICE_LABEL) or labels.get("service") or labels.get("job")
                if service and service_value and str(service_value) != service:
                    continue
                active_at = item.get("activeAt") or item.get("active_at") or item.get("timestamp")
                timestamp = self._dt(active_at)
                if since and timestamp < since:
                    continue
                annotations = item.get("annotations") or {}
                alerts.append(Alert(
                    source="prometheus",
                    source_id=str(item.get("fingerprint") or labels.get("alertname") or len(alerts)),
                    severity=str(labels.get("severity") or item.get("severity") or "unknown"),
                    service=str(service_value or service or "unknown"),
                    message=str(annotations.get("summary") or annotations.get("description") or labels.get("alertname") or "Prometheus alert"),
                    timestamp=timestamp,
                    raw_data=item,
                ))
                if len(alerts) >= min(max(int(limit), 1), 500):
                    return alerts
        return alerts
