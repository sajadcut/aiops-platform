from datetime import datetime, timezone

import pytest

from apps.context_service.evidence_collector import EvidenceCollector
from integrations.base import Alert, LogEntry, MetricPoint


class FakeZabbix:
    def __init__(self):
        self.services = []

    async def get_alerts(self, since=None, service=None, limit=100):
        self.services.append(service)
        return [Alert(
            source="zabbix",
            source_id="evt-1",
            severity="high",
            service="payment-worker",
            message="High CPU",
            timestamp=datetime.now(timezone.utc),
            raw_data={
                "host": {
                    "hostid": "88",
                    "host": "pay-win-01",
                    "inventory": {"os_full": "Windows Server 2022"},
                    "groups": [{"name": "Production VMs"}],
                    "parentTemplates": [{"name": "Windows by Zabbix agent"}],
                    "tags": [
                        {"tag": "asset_type", "value": "vm"},
                        {"tag": "service", "value": "payment-worker"},
                        {"tag": "environment", "value": "prod"},
                    ],
                },
            },
        )]


class FakeElastic:
    def __init__(self):
        self.services = []

    async def get_logs(self, service, since, until=None, level=None, limit=100):
        self.services.append(service)
        return [LogEntry(
            timestamp=datetime.now(timezone.utc),
            service=service,
            level="warning",
            message="CPU pressure",
            source="elasticsearch",
            raw_data={
                "host": {"name": "pay-win-01", "os": {"family": "windows", "version": "2022"}},
                "service": {"name": "payment-worker", "environment": "prod"},
            },
        )]


class FakePrometheus:
    def __init__(self):
        self.services = []

    async def get_metrics(self, service, metric_names, since, until=None):
        self.services.append(service)
        return [MetricPoint(
            timestamp=datetime.now(timezone.utc),
            service=service,
            name="cpu_usage",
            value=96.0,
            labels={"service": service, "instance": "pay-win-01:9182", "os": "windows", "environment": "prod"},
            source="prometheus",
        )]


class FailIfCalledVM:
    async def collect_metrics(self, service):
        raise AssertionError("Linux SSH telemetry must not run for Windows assets")


@pytest.mark.asyncio
async def test_unknown_service_is_resolved_from_zabbix_before_other_sources():
    zabbix, elastic, prom = FakeZabbix(), FakeElastic(), FakePrometheus()
    collector = EvidenceCollector(zabbix=zabbix, elasticsearch=elastic, prometheus=prom, vm=FailIfCalledVM())
    result = await collector.collect("unknown", datetime.now(timezone.utc))

    assert zabbix.services == [None]
    assert elastic.services == ["payment-worker"]
    assert prom.services == ["payment-worker"]
    assert result["service"] == "payment-worker"
    assert result["asset_context"]["asset_type"] == "vm"
    assert result["asset_context"]["os_family"] == "windows"
    assert result["asset_context"]["hostname"] == "pay-win-01"
    assert {item["source"] for item in result["evidence"]} >= {"zabbix", "elasticsearch", "prometheus"}
