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
    assert reason["status"] == "incident_service_conflict"


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
    async def isolated_followup(*args, **kwargs):
        return {"status": "isolated_test_no_database", "reassessed": False}
    monkeypatch.setattr(api, "persist_and_reassess", isolated_followup)
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
    async def isolated_followup(*args, **kwargs):
        return {"status": "isolated_test_no_database", "reassessed": False}
    monkeypatch.setattr(api, "persist_and_reassess", isolated_followup)
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


def test_incident_service_card_prefers_newest_verified_vm_mcp_over_initial_alert():
    from apps.api.incident_chat import _observed_status
    older = vm_fact(success=True, active_state="failed", sub_state="failed", result="timeout")
    older["created_at"] = "2026-10-14T08:12:39Z"
    live_chat = {
        "event_id": "22222222-2222-4222-8222-222222222222",
        "event_type": "incident_copilot_read", "action": "service_status",
        "created_at": "2026-10-14T08:18:10Z",
        "metadata": {"observation": {
            "success": True, "diagnostic": "service_status", "service": "gfpapi",
            "target": "10.248.16.82", "active_state": "active",
            "sub_state": "running", "result": "success",
        }},
    }
    status = _observed_status("gfpapi", "10.248.16.82", [older], [live_chat])
    assert status["status"] == "running"
    assert status["source"] == "vm_mcp_chat"
    assert status["observed_at"].startswith("2026-10-14T08:18:10")
    assert status["verified_systemd_only"] is True


def test_service_card_never_trusts_cross_service_or_unauthenticated_observations():
    from apps.api.incident_chat import _observed_status
    wrong = vm_fact(service="nginx", success=True, active_state="active", sub_state="running")
    wrong["created_at"] = "2026-10-14T08:19:00Z"
    bad = vm_fact(success=False, active_state="active", sub_state="running")
    bad["created_at"] = "2026-10-14T08:20:00Z"
    different_host = vm_fact(success=True, target="10.248.16.99",
                             active_state="active", sub_state="running")
    different_host["created_at"] = "2026-10-14T08:21:00Z"
    result = _observed_status("gfpapi", "10.248.16.82",
                              [wrong, bad, different_host], [])
    assert result["status"] == "unknown"
    assert result["verified_systemd_only"] is False


def test_failed_recheck_overrides_old_running_but_not_mutates_old_evidence():
    from apps.api.incident_chat import _observed_status
    recorded = vm_fact(success=True, active_state="active", sub_state="running")
    recorded["created_at"] = "2026-10-14T08:12:39Z"
    failed = {
        "event_type": "incident_service_status_rechecked",
        "status": "unavailable", "created_at": "2026-10-14T08:20:00Z",
        "metadata": {"reason": "vm_mcp_live_identity_check_failed"},
    }
    result = _observed_status("gfpapi", "10.248.16.82", [recorded], [failed])
    assert result["status"] == "unknown"
    assert result["source"] == "vm_mcp_recheck_failed"
    assert recorded["raw_data"]["active_state"] == "active"


def test_active_but_not_running_is_not_labeled_running():
    from apps.api.incident_chat import _observed_status
    recorded = vm_fact(success=True, active_state="active", sub_state="exited")
    recorded["created_at"] = "2026-10-14T08:12:39Z"
    result = _observed_status("gfpapi", "10.248.16.82", [recorded], [])
    assert result["status"] == "active"


@pytest.mark.asyncio
async def test_click_recheck_calls_only_readonly_service_status_and_writes_audit(monkeypatch):
    import apps.api.incident_chat as api
    calls = []
    class Db:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class Audit:
        def __init__(self, db): pass
        async def append(self, event): calls.append(("audit", event))
    async def scope(db, incident_id):
        return (SimpleNamespace(service="gfpapi"), [vm_fact()],
                incident_context(),
                {"candidate": "10.248.16.82"})
    async def read_status(service, evidence, context, *, force_live):
        calls.append(("mcp", service, force_live))
        return {"target": "10.248.16.82", "service": "gfpapi"}, {
            "live_observation": {"success": True, "target": "10.248.16.82",
                                 "service": "gfpapi", "active_state": "active",
                                 "sub_state": "running", "result": "success"}}
    monkeypatch.setattr(api, "AsyncSessionLocal", Db)
    async def isolated_followup(*args, **kwargs):
        return {"status": "isolated_test_no_database", "reassessed": False}
    monkeypatch.setattr(api, "persist_and_reassess", isolated_followup)
    monkeypatch.setattr(api, "_incident_status_scope", scope)
    monkeypatch.setattr(api, "resolve_vm_binding", read_status)
    monkeypatch.setattr(api, "PostgreSQLAuditStore", Audit)
    result = await api.recheck_incident_service_status(
        UUID("11111111-1111-4111-8111-111111111111"),
        identity=SimpleNamespace(subject="sre-test"),
    )
    assert result["status"] == "running"
    assert result["source"] == "vm_mcp_recheck"
    assert calls[0] == ("mcp", "gfpapi", True)
    assert calls[1][1]["event_type"] == "incident_service_status_rechecked"
    assert calls[1][1]["status"] == "success"
    assert calls[1][1]["actor"] == "sre-test"


@pytest.mark.asyncio
async def test_recheck_refuses_ambiguous_target_and_makes_no_remote_call(monkeypatch):
    import apps.api.incident_chat as api
    class Db:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    async def scope(db, incident_id):
        return (SimpleNamespace(service="gfpapi"), [vm_fact()],
                incident_context(),
                {"candidate": None, "reason": "conflicting_vm_targets"})
    async def forbidden(*args, **kwargs):
        raise AssertionError("unsafe SSH call")
    monkeypatch.setattr(api, "AsyncSessionLocal", Db)
    async def isolated_followup(*args, **kwargs):
        return {"status": "isolated_test_no_database", "reassessed": False}
    monkeypatch.setattr(api, "persist_and_reassess", isolated_followup)
    monkeypatch.setattr(api, "_incident_status_scope", scope)
    monkeypatch.setattr(api, "resolve_vm_binding", forbidden)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await api.recheck_incident_service_status(
            UUID("11111111-1111-4111-8111-111111111111"),
            identity=SimpleNamespace(subject="operator"),
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["reason"] == "conflicting_vm_targets"
