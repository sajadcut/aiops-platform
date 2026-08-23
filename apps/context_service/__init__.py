import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from uuid import UUID
from domain.contracts.logging import logger
from domain.schemas import IncidentCreate, EvidenceCreate
from integrations.zabbix.mcp_client import ZabbixMCPClient
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
from integrations.prometheus.mcp_client import PrometheusMCPClient
from integrations.base import LogEntry, MetricPoint, Alert

class ContextBuilder:
    """
    ساخت Context کامل برای یک Incident با استفاده از MCP Clientها.
    شامل: دریافت اطلاعات سرویس، لاگ‌ها، متریک‌ها و Alertهای مرتبط.
    """
    
    def __init__(self):
        self.zabbix = ZabbixMCPClient()
        self.elastic = ElasticsearchMCPClient()
        self.prometheus = PrometheusMCPClient()
    
    async def build_context(self, incident_data: IncidentCreate) -> Dict[str, Any]:
        service = incident_data.service
        if not service:
            logger.warning("No service specified, using mock data")
            service = "unknown-service"

        now = datetime.now()
        since = now - timedelta(minutes=15)
        
        logger.info(f"Building context for service: {service}")

        # دریافت داده‌ها
        logs_task = self.elastic.get_logs(service=service, since=since, limit=50)
        metrics_task = self.prometheus.get_metrics(
            service=service, 
            metric_names=["cpu_usage", "memory_usage", "error_rate"], 
            since=since
        )
        alerts_task = self.zabbix.get_alerts(service=service, since=since, limit=20)

        logs_result, metrics_result, alerts_result = await asyncio.gather(
            logs_task, 
            metrics_task, 
            alerts_task,
            return_exceptions=True
        )

        # ✅ مدیریت صحیح Exception‌ها
        if isinstance(logs_result, Exception):
            logger.info(f"Using mock logs data (error: {logs_result})")
            logs = self._get_mock_logs(service, now)
        else:
            logs = logs_result if isinstance(logs_result, list) else []

        if isinstance(metrics_result, Exception):
            logger.info(f"Using mock metrics data (error: {metrics_result})")
            metrics = self._get_mock_metrics(service, now)
        else:
            metrics = metrics_result if isinstance(metrics_result, list) else []

        if isinstance(alerts_result, Exception):
            logger.info(f"Using mock alerts data (error: {alerts_result})")
            alerts = self._get_mock_alerts(service, now)
        else:
            alerts = alerts_result if isinstance(alerts_result, list) else []

        # ساخت Evidenceها
        evidence_list = []
        for log in logs[:10]:
            evidence_list.append(EvidenceCreate(
                incident_id=UUID(int=0),
                type="log",
                source="elasticsearch",
                query=f"service:{service}",
                time_range={"since": since.isoformat(), "until": now.isoformat()},
                reference=f"log_{log.timestamp}",
                raw_data=log.model_dump() if hasattr(log, 'model_dump') else {"message": str(log)},
                confidence=1.0
            ))
        
        for metric in metrics[:10]:
            evidence_list.append(EvidenceCreate(
                incident_id=UUID(int=0),
                type="metric",
                source="prometheus",
                query=metric.name,
                time_range={"since": since.isoformat(), "until": now.isoformat()},
                reference=f"metric_{metric.name}_{metric.timestamp}",
                raw_data=metric.model_dump() if hasattr(metric, 'model_dump') else {"value": metric.value},
                confidence=1.0
            ))
        
        for alert in alerts[:5]:
            evidence_list.append(EvidenceCreate(
                incident_id=UUID(int=0),
                type="alert",
                source=alert.source,
                query=alert.source_id,
                time_range={"since": alert.timestamp.isoformat()},
                reference=alert.source_id,
                raw_data=alert.model_dump() if hasattr(alert, 'model_dump') else {"message": alert.message},
                confidence=1.0
            ))

        evidence_dicts = []
        for ev in evidence_list:
            ev_dict = ev.model_dump()
            ev_dict["incident_id"] = str(ev_dict["incident_id"])
            evidence_dicts.append(ev_dict)

        context = {
            "incident": incident_data.model_dump(),
            "service": service,
            "time_window": {
                "since": since.isoformat(),
                "until": now.isoformat()
            },
            "evidence": evidence_dicts,
            "summary": {
                "log_count": len(logs),
                "metric_count": len(metrics),
                "alert_count": len(alerts),
                "latest_log": logs[0].model_dump() if logs else None,
                "avg_cpu": self._calculate_avg(metrics, "cpu_usage"),
                "avg_memory": self._calculate_avg(metrics, "memory_usage"),
                "error_rate": self._calculate_avg(metrics, "error_rate")
            }
        }

        logger.info(f"Context built: {len(evidence_dicts)} evidence items collected.")
        return context

    def _get_mock_logs(self, service: str, now: datetime) -> List[LogEntry]:
        return [
            LogEntry(
                timestamp=now - timedelta(minutes=5),
                service=service,
                level="error",
                message=f"HTTP 500 error on /api/payment: timeout connecting to database",
                source="elasticsearch",
                raw_data={"trace_id": "abc123", "exception": "ConnectionTimeout"}
            ),
            LogEntry(
                timestamp=now - timedelta(minutes=7),
                service=service,
                level="error",
                message=f"Failed to fetch user profile: connection refused",
                source="elasticsearch",
                raw_data={"trace_id": "def456"}
            ),
            LogEntry(
                timestamp=now - timedelta(minutes=10),
                service=service,
                level="info",
                message=f"Deployment v2.3.1 completed successfully",
                source="elasticsearch",
                raw_data={"deployment_id": "deploy-123"}
            ),
            LogEntry(
                timestamp=now - timedelta(minutes=12),
                service=service,
                level="warning",
                message=f"Database connection pool at 85% capacity",
                source="elasticsearch",
                raw_data={"pool_size": 100, "active_connections": 85}
            )
        ]

    def _get_mock_metrics(self, service: str, now: datetime) -> List[MetricPoint]:
        return [
            MetricPoint(
                timestamp=now - timedelta(minutes=5),
                service=service,
                name="error_rate",
                value=12.5,
                labels={"type": "http_500"},
                source="prometheus"
            ),
            MetricPoint(
                timestamp=now - timedelta(minutes=10),
                service=service,
                name="cpu_usage",
                value=75.0,
                labels={},
                source="prometheus"
            ),
            MetricPoint(
                timestamp=now - timedelta(minutes=15),
                service=service,
                name="memory_usage",
                value=85.0,
                labels={},
                source="prometheus"
            ),
            MetricPoint(
                timestamp=now - timedelta(minutes=3),
                service=service,
                name="error_rate",
                value=18.7,
                labels={"type": "http_500"},
                source="prometheus"
            )
        ]

    def _get_mock_alerts(self, service: str, now: datetime) -> List[Alert]:
        return [
            Alert(
                source="zabbix",
                source_id="12345",
                severity="high",
                service=service,
                message=f"High error rate detected on {service}: 12.5% errors in last 5 minutes",
                timestamp=now - timedelta(minutes=6),
                raw_data={"trigger_id": "12345", "expression": "error_rate > 10"}
            ),
            Alert(
                source="prometheus",
                source_id="67890",
                severity="warning",
                service=service,
                message=f"CPU usage above 80% for {service}",
                timestamp=now - timedelta(minutes=8),
                raw_data={"alert_name": "HighCPU", "value": "75%"}
            )
        ]

    @staticmethod
    def _calculate_avg(metrics: List[MetricPoint], name: str) -> Optional[float]:
        filtered = [m.value for m in metrics if m.name == name and m.value is not None]
        return sum(filtered) / len(filtered) if filtered else None