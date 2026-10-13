"""GFPAPI incident chat: recover real VM identity and keep execution fail-closed."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

from apps.incident_copilot import vm_binding
from apps.incident_vm_identity import (
    incident_vm_context, vm_binding_diagnostic, resolve_vm_binding,
    vm_status_answer,
)


def vm_fact(*, success=True, target="10.248.16.82", service="gfpapi",
            action="service_status", **fields):
    return {
        "source": "vm_mcp", "reference": "vm:status",
        "raw_data": {
            "diagnostic": action, "service": service,
            "target": target, "success": success, **fields,
        },
    }


def incident_context(*, target="10.248.16.82", service="gfpapi"):
    return {"trigger_signal": {
        "source": "zabbix", "payload": {
            "platform": "vm", "service": service,
            "target_ip": target,
        },
    }}


def test_incomplete_old_vm_status_can_be_rechecked_but_not_bound_without_live_proof():
    old = vm_fact(success=False, active_state="failed", result="timeout")
    context = incident_context()
    assert vm_binding("gfpapi", [old], context) is None
    diagnosis = vm_binding_diagnostic("gfpapi", [old], context)
    assert diagnosis["candidate"] == "10.248.16.82"
    assert diagnosis["reason"] == "live_service_identity_check_required"


@pytest.mark.asyncio
async def test_authenticated_live_failed_unit_rebinds_with_provenance_without_execution():
    class FakeVM:
        def __init__(self):
            self.calls = []
        async def service_status(self, target, service):
            self.calls.append((target, service))
            return {
                "success": True, "service": service, "target": target,
                "active_state": "failed", "sub_state": "failed",
                "load_state": "loaded", "result": "timeout",
            }
    client = FakeVM()
    binding, result = await resolve_vm_binding(
        "gfpapi", [vm_fact(success=False, active_state="failed")],
        incident_context(), connector=client, force_live=True,
    )
    assert client.calls == [("10.248.16.82", "gfpapi")]
    assert binding["target"] == "10.248.16.82"
    assert binding["active_state"] == "failed"
    assert binding["read_only_verified"] is True
    assert result["status"] == "verified_from_live_vm_mcp"
    assert "ActiveState=failed" in vm_status_answer(result["live_observation"])


@pytest.mark.asyncio
async def test_zabbix_incident_candidate_requires_real_corresponding_vm_mcp_result():
    class VM:
        async def service_status(self, target, service):
            return {"success": True, "target": "10.248.16.99",
                    "service": service, "active_state": "failed"}
    binding, reason = await resolve_vm_binding(
        "gfpapi", [], incident_context(), connector=VM(),
    )
    assert binding is None
    assert reason["status"] == "vm_mcp_live_identity_mismatch"


@pytest.mark.asyncio
async def test_failed_status_does_not_mean_unverified_identity():
    class VM:
        async def service_status(self, target, service):
            return {"success": True, "target": target,
                    "service": service, "active_state": "failed"}
    bind, _ = await resolve_vm_binding(
        "gfpapi", [], incident_context(), connector=VM(),
    )
    assert bind and bind["service"] == "gfpapi"


@pytest.mark.asyncio
async def test_another_target_or_service_is_never_used_for_live_probe():
    class VM:
        async def service_status(self, *args):
            raise AssertionError("conflicting identity must never call VM")
    evidence = [vm_fact(), vm_fact(target="10.248.16.83")]
    bound, reason = await resolve_vm_binding(
        "gfpapi", evidence, incident_context(), connector=VM(),
    )
    assert bound is None
    assert reason["status"] == "conflicting_vm_targets"
    bound, reason = await resolve_vm_binding(
        "gfpapi", [vm_fact()], incident_context(target="10.248.16.83"), connector=VM(),
    )
    assert bound is None
    assert reason["status"] == "alert_vm_target_conflict"
    bound, reason = await resolve_vm_binding(
        "gfpapi", [vm_fact()], incident_context(service="nginx"), connector=VM(),
    )
    assert bound is None
    assert reason["status"] == "verified_target_not_in_incident_evidence" or reason["status"] == "alert_vm_target_conflict"


@pytest.mark.asyncio
async def test_missing_vm_or_unreadable_vm_never_becomes_an_approval():
    class VM:
        async def service_status(self, *args):
            return {"success": False, "target": "10.248.16.82",
                    "service": "gfpapi", "active_state": "failed"}
    bound, reason = await resolve_vm_binding(
        "gfpapi", [], incident_context(), connector=VM(),
    )
    assert bound is None
    assert reason["status"] == "vm_mcp_service_status_unavailable"


def test_incident_and_checkpoint_identity_conflicts_are_not_overwritten():
    lhs = incident_context()
    rhs = {"state": {"context": incident_context(target="10.248.16.83")}}
    ctx = incident_vm_context(lhs, rhs)
    assert ctx["_vm_identity_context_conflicts"] == ["target_ip"]
    diagnosis = vm_binding_diagnostic("gfpapi", [vm_fact()], ctx)
    assert diagnosis["reason"] == "incident_identity_context_conflict"
    assert diagnosis["candidate"] is None


@pytest.mark.asyncio
async def test_screenshot_status_uses_authenticated_vm_mcp_and_not_stale_agent_interpretation(monkeypatch):
    import apps.api.incident_chat as api
    import apps.incident_vm_identity as identity_module
    class Db:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class Audit:
        def __init__(self, db): pass
        async def list(self, *args): return []
        async def append(self, item): pass
    async def fake_scope(db, incident_id):
        return SimpleNamespace(service="gfpapi", context=incident_context()), {
            "state": {"context": incident_context()},
        }, [vm_fact(success=False, active_state="failed", sub_state="failed")]
    async def brief(*args):
        return {"incident_summary": {"service": "gfpapi"}}
    async def llm(*args, **kwargs):
        return {"intent": "service_status", "answer": "وضعیت نامشخص است.",
                "model_status": "structured", "reason": ""}
    async def append(*args, **kwargs):
        return "audit-turn"
    class VM:
        async def service_status(self, target, service):
            return {"success": True, "target": target, "service": service,
                    "load_state": "loaded", "active_state": "failed",
                    "sub_state": "failed", "result": "timeout"}
    monkeypatch.setattr(identity_module, "VMEdgeMCPClient", lambda: VM())
    monkeypatch.setattr(api, "AsyncSessionLocal", Db)
    monkeypatch.setattr(api, "_scope", fake_scope)
    monkeypatch.setattr(api, "PostgreSQLAuditStore", Audit)
    monkeypatch.setattr(api, "load_decision_brief_for_incident", brief)
    monkeypatch.setattr(api, "llm_plan", llm)
    monkeypatch.setattr(api, "append_turn", append)
    incident_id = UUID("11111111-1111-4111-8111-111111111111")
    result = await api.incident_chat_message(
        incident_id, api.IncidentChatMessage(message="وضعیت سرویس چیه"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert result["answer_basis"] == "live_mcp"
    assert "ActiveState=failed" in result["message"]
    assert "Result=timeout" in result["message"]
    assert "target_not_verified" not in result["message"]


@pytest.mark.asyncio
async def test_operator_start_after_failed_live_check_requires_explicit_restart_approval(monkeypatch):
    import apps.api.incident_chat as api
    import apps.incident_vm_identity as identity_module
    class Db:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class Audit:
        def __init__(self, db): pass
        async def list(self, *args): return []
    async def fake_scope(db, incident_id):
        return SimpleNamespace(service="gfpapi", context=incident_context()), {
            "state": {"context": incident_context()},
        }, [vm_fact(success=False, active_state="failed")]
    async def brief(*args):
        return {"incident_summary": {"service": "gfpapi"}}
    async def llm(*args, **kwargs):
        return {"intent": "propose_start", "answer": "استارت کردم!",
                "model_status": "structured", "reason": ""}
    async def append(*args, **kwargs):
        return "audit-turn"
    class VM:
        async def service_status(self, target, service):
            return {"success": True, "target": target, "service": service,
                    "load_state": "loaded", "active_state": "failed"}
    monkeypatch.setattr(identity_module, "VMEdgeMCPClient", lambda: VM())
    monkeypatch.setattr(api, "AsyncSessionLocal", Db)
    monkeypatch.setattr(api, "_scope", fake_scope)
    monkeypatch.setattr(api, "PostgreSQLAuditStore", Audit)
    monkeypatch.setattr(api, "load_decision_brief_for_incident", brief)
    monkeypatch.setattr(api, "llm_plan", llm)
    monkeypatch.setattr(api, "append_turn", append)
    result = await api.incident_chat_message(
        UUID("11111111-1111-4111-8111-111111111111"),
        api.IncidentChatMessage(message="استارتش کن"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert result["kind"] == "action_proposal"
    assert result["proposal"]["requested_action"] == "start_service"
    assert result["proposal"]["action"] == "restart_service"
    assert result["proposal"]["target"] == "10.248.16.82"
    assert result["proposal"]["execution_authority"] is False
    assert "Restart" in result["message"]
    assert "استارت کردم" not in result["message"]
