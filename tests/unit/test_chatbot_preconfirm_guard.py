import pytest

import apps.chatbot.service as chatbot_module
from apps.chatbot.service import ChatbotService


def _proposal():
    return {
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "tool_name": "ssh_vm",
        "action": "restart_service",
        "target": "10.100.6.199",
        "parameters": {"service": "nginx", "target_port": 86},
    }


@pytest.mark.asyncio
async def test_preconfirm_guard_uses_fresh_vm_runbook_evidence(monkeypatch):
    observed = {}

    async def snapshot(**kwargs):
        observed["snapshot"] = kwargs
        return {
            "read_success": True,
            "error": None,
            "evidence": [{"reference": "svc-failed"}],
            "context": {"live_evidence": {"evidence": [{"reference": "svc-failed"}]}},
        }

    def preflight(**kwargs):
        observed["preflight"] = kwargs
        return {
            "safe_to_execute": True,
            "reason": "fresh_execution_preconditions_satisfied",
            "evidence_refs": ["svc-failed"],
        }

    monkeypatch.setattr(
        chatbot_module.RunbookRuntimeGuard,
        "collect_snapshot",
        snapshot,
    )
    monkeypatch.setattr(
        chatbot_module.RunbookRuntimeGuard,
        "preflight",
        preflight,
    )

    result = await ChatbotService()._preconfirm_mutation_guard(_proposal())

    assert result["applies"] is True
    assert result["safe_to_execute"] is True
    assert result["stale"] is False
    assert observed["snapshot"]["phase"] == "chatbot_preconfirm"
    assert observed["snapshot"]["target"] == "10.100.6.199"
    assert observed["snapshot"]["parameters"]["service"] == "nginx"
    assert observed["preflight"]["action"] == "restart_service"
    assert observed["preflight"]["tool_name"] == "ssh_vm"


@pytest.mark.asyncio
async def test_preconfirm_guard_marks_recovered_service_as_stale(monkeypatch):
    async def snapshot(**_kwargs):
        return {
            "read_success": True,
            "error": None,
            "evidence": [{"reference": "svc-active"}],
            "context": {"live_evidence": {"evidence": [{"reference": "svc-active"}]}},
        }

    monkeypatch.setattr(
        chatbot_module.RunbookRuntimeGuard,
        "collect_snapshot",
        snapshot,
    )
    monkeypatch.setattr(
        chatbot_module.RunbookRuntimeGuard,
        "preflight",
        lambda **_kwargs: {
            "safe_to_execute": False,
            "reason": "service_no_longer_unhealthy",
            "evidence_refs": ["svc-active"],
        },
    )

    result = await ChatbotService()._preconfirm_mutation_guard(_proposal())

    assert result["safe_to_execute"] is False
    assert result["stale"] is True
    assert result["reason"] == "service_no_longer_unhealthy"


@pytest.mark.asyncio
async def test_preconfirm_guard_keeps_transient_telemetry_failure_retryable(monkeypatch):
    async def snapshot(**_kwargs):
        return {
            "read_success": False,
            "error": "vm_telemetry_unavailable",
            "evidence": [],
            "context": {"live_evidence": {"evidence": []}},
        }

    monkeypatch.setattr(
        chatbot_module.RunbookRuntimeGuard,
        "collect_snapshot",
        snapshot,
    )
    monkeypatch.setattr(
        chatbot_module.RunbookRuntimeGuard,
        "preflight",
        lambda **_kwargs: {
            "safe_to_execute": False,
            "reason": "fresh_service_status_missing",
            "evidence_refs": [],
        },
    )

    result = await ChatbotService()._preconfirm_mutation_guard(_proposal())

    assert result["safe_to_execute"] is False
    assert result["stale"] is False
    assert result["reason"] == "fresh_service_status_missing"
    assert result["snapshot"]["error"] == "vm_telemetry_unavailable"


@pytest.mark.asyncio
async def test_preconfirm_guard_does_not_invent_contract_for_other_tools():
    proposal = {
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "tool_name": "kubernetes_mcp",
        "action": "restart_workload",
        "target": "payment-api",
        "parameters": {"namespace": "payments"},
    }

    result = await ChatbotService()._preconfirm_mutation_guard(proposal)

    assert result["applies"] is False
    assert result["safe_to_execute"] is True
    assert result["reason"] == "runtime_guard_not_required"
