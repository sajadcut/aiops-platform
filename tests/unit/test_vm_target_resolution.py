from datetime import datetime, timezone

import pytest

from apps.context_service.evidence_collector import EvidenceCollector
from integrations.vm.target_context import (
    bind_vm_target,
    reset_vm_target,
    target_from_zabbix_payload,
)


class _RecordingVM:
    def __init__(self):
        self.targets = []

    async def collect_vm_metrics(self, target):
        self.targets.append(target)
        return {
            "success": True,
            "metrics": {
                "cpu_usage": 12.5,
                "memory_usage": 34.0,
            },
        }


def test_zabbix_vm_target_resolution_prefers_target_ip_and_never_service():
    payload = {
        "target_ip": "10.100.6.199",
        "host": "NeoBanking-6.199",
        "service": "haproxy",
    }
    assert target_from_zabbix_payload(payload) == "10.100.6.199"
    assert target_from_zabbix_payload({"host": "NeoBanking-6.199", "service": "haproxy"}) == "NeoBanking-6.199"
    assert target_from_zabbix_payload({"service": "haproxy"}) is None


def test_asset_vm_target_resolution_does_not_fall_back_to_service():
    assert EvidenceCollector._vm_target_from_asset({"service": "haproxy"}) is None
    assert EvidenceCollector._vm_target_from_asset({
        "service": "haproxy",
        "hostname": "NeoBanking-6.199",
    }) == "NeoBanking-6.199"
    assert EvidenceCollector._vm_target_from_asset({
        "service": "haproxy",
        "hostname": "NeoBanking-6.199",
        "ip_addresses": ["10.100.6.199"],
    }) == "10.100.6.199"


@pytest.mark.asyncio
async def test_vm_telemetry_uses_request_target_not_service_name():
    vm = _RecordingVM()
    collector = EvidenceCollector(vm=vm)
    token = bind_vm_target("10.100.6.199")
    try:
        result = await collector.collect_requested(
            "haproxy",
            datetime.now(timezone.utc),
            [{"evidence_type": "telemetry", "preferred_source": "vm"}],
        )
    finally:
        reset_vm_target(token)

    assert vm.targets == ["10.100.6.199"]
    assert result["service"] == "haproxy"
    assert result["vm_target"] == "10.100.6.199"
    vm_metrics = [item for item in result["evidence"] if item.get("source") == "vm_mcp"]
    assert vm_metrics
    assert all(item["raw_data"]["target"] == "10.100.6.199" for item in vm_metrics if item.get("type") == "metric")
    assert all(item["raw_data"].get("service") == "haproxy" for item in vm_metrics if item.get("type") == "metric")
