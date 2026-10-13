"""Reproduction: Oct 13 20:20 GFPAPI false conflict from unrelated Cognia nginx."""
from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest

from apps.context_service.service_identity import ServiceIdentityResolver
from apps.incident_copilot import fallback_intent, vm_binding
from apps.incident_vm_identity import (
    incident_vm_context, resolve_vm_binding, vm_binding_diagnostic,
)


NGINX_KNOWLEDGE = {
    "fields": {"service": "nginx", "platform": "vm"},
    "field_sources": {"service": "cognia:1:115:126:2425"},
    "source_refs": ["cognia:1:115:126:2425"],
    "conflicts": [],
}
TRIGGER = {
    "trigger_signal": {
        "source": "zabbix",
        "payload": {
            "eventid": "9991882022dd66322922",
            "name": "GFPAPI Systemd Service Down",
            "service": "gfpapi",
            "target_ip": "10.248.16.82",
            "host_ip": "10.248.16.82",
            "platform": "vm",
        },
    },
}


def identity_with_cognia_conflict():
    return ServiceIdentityResolver.resolve(
        source_service="gfpapi",
        live_asset={"service": "gfpapi", "platform": "vm"},
        knowledge_topology=NGINX_KNOWLEDGE,
        live_service_verified=True,
    )


def old_evidence(*, success=True):
    return [{
        "source": "vm_mcp",
        "reference": "577e2f1b-21bd-49b4-bb5a-89286b9f6a24",
        "raw_data": {
            "diagnostic": "service_status",
            "target": "10.248.16.82",
            "service": "gfpapi", "success": success,
            "active_state": "failed", "sub_state": "failed",
            "result": "timeout",
        },
    }]


def test_oct_13_repro_keeps_nginx_cognia_disagreement_but_identity_is_verified():
    result = identity_with_cognia_conflict()
    ident = result["service_identity"]
    assert ident["service"] == "gfpapi"
    assert ident["status"] == "verified"
    assert ident["verified"] is True
    assert ident["conflicts"] == [{
        "field": "service", "live": "gfpapi", "knowledge": "nginx",
        "knowledge_source": "cognia:1:115:126:2425",
        "kind": "live_vs_knowledge",
    }]
    assert ident["blocking_conflicts"] == []
    assert ident["advisory_knowledge_conflicts"] == ident["conflicts"]
    assert ident["requires_more_evidence"] is False
    assert result["asset_context"]["service_identity_unverified"] is False
    assert result["topology_context"]["topology_conflicts"] == ident["conflicts"]


def test_original_and_checkpoint_cognia_disagreements_do_not_create_identity_conflict():
    identity = identity_with_cognia_conflict()["service_identity"]
    initial = {**TRIGGER, "service_identity": {"service": "gfpapi",
                                                 "status": "reported", "conflicts": []}}
    checkpoint = {"state": {"context": {
        **TRIGGER, "service_identity": identity,
    }}}
    merged = incident_vm_context(initial, checkpoint)
    assert "_vm_identity_context_conflicts" not in merged
    diagnostic = vm_binding_diagnostic("gfpapi", old_evidence(success=False), merged)
    assert diagnostic["candidate"] == "10.248.16.82"
    assert diagnostic["reason"] == "live_service_identity_check_required"
    assert diagnostic["advisory_knowledge_conflict_count"] == 1


@pytest.mark.asyncio
async def test_live_mcp_validates_gfpapi_despite_cognia_nginx_but_does_not_grant_restart():
    ctx = {**TRIGGER, "service_identity":
           identity_with_cognia_conflict()["service_identity"]}
    requests = []
    class VM:
        async def service_status(self, target, service):
            requests.append((target, service))
            return {"success": True, "target": target, "service": service,
                    "load_state": "loaded", "active_state": "failed",
                    "sub_state": "failed", "result": "timeout"}
    bound, result = await resolve_vm_binding(
        "gfpapi", old_evidence(success=False), ctx,
        connector=VM(), force_live=True,
    )
    assert requests == [("10.248.16.82", "gfpapi")]
    assert bound["service"] == "gfpapi" and bound["target"] == "10.248.16.82"
    assert bound["active_state"] == "failed"
    assert bound["read_only_verified"] is True
    assert result["advisory_knowledge_conflict_count"] == 1


def test_real_conflicts_remain_blocked_even_with_cognia_advisory():
    ident = identity_with_cognia_conflict()["service_identity"]
    ident["conflicts"].append({
        "kind": "source_vs_live_service", "field": "service",
        "source": "gfpapi", "observed": "nginx",
    })
    ctx = {**TRIGGER, "service_identity": ident}
    diag = vm_binding_diagnostic("gfpapi", old_evidence(), ctx)
    assert diag["reason"] == "service_identity_conflict"
    assert diag["candidate"] is None
    assert vm_binding("gfpapi", old_evidence(), ctx) is None
    # Unknown/malformed conflict kinds must not accidentally be advisory.
    for conflict in ({"kind": "new_vendor_identity_conflict"}, "not-an-object"):
        ctx["service_identity"]["conflicts"] = [conflict]
        diag = vm_binding_diagnostic("gfpapi", old_evidence(), ctx)
        assert diag["reason"] == "service_identity_conflict"


def test_multiple_live_hosts_and_source_mismatch_remain_blocked_with_cognia_advisory():
    ctx = {**TRIGGER, "service_identity":
           identity_with_cognia_conflict()["service_identity"]}
    rows = old_evidence()
    other = {**rows[0], "raw_data": {
        **rows[0]["raw_data"], "target": "10.248.16.83",
    }}
    assert vm_binding_diagnostic("gfpapi", [*rows, other], ctx)["reason"] == "conflicting_vm_targets"
    mismatch = {**ctx, "trigger_signal": {
        **TRIGGER["trigger_signal"],
        "payload": {**TRIGGER["trigger_signal"]["payload"],
                    "target_ip": "10.248.16.83", "host_ip": "10.248.16.83"},
    }}
    assert vm_binding_diagnostic("gfpapi", rows, mismatch)["reason"] == "alert_vm_target_conflict"


@pytest.mark.parametrize("command, expected", [
    ("ری استارتش کن", "propose_restart"),
    ("ری‌استارتش کن", "propose_restart"),
    ("ریستارتش کن", "propose_restart"),
    ("restart service", "propose_restart"),
    ("استارتش کن", "propose_start"),
])
def test_persian_operator_recovery_intents_work_with_llm_unavailable(command, expected):
    assert fallback_intent(command) == expected


@pytest.mark.asyncio
async def test_actual_chat_cognia_conflict_reaches_mcp_for_status_and_restart(monkeypatch):
    import apps.api.incident_chat as api
    import apps.incident_vm_identity as identity_module

    ident = identity_with_cognia_conflict()["service_identity"]
    ctx = {**TRIGGER, "service_identity": ident}
    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class Audit:
        def __init__(self, db): pass
        async def list(self, *args): return []
        async def append(self, *args): pass
    async def scope(db, iid):
        return SimpleNamespace(service="gfpapi", context=TRIGGER), {
            "state": {"context": ctx},
        }, old_evidence(success=False)
    async def brief(db, iid):
        return {"incident_summary": {"service": "gfpapi"}}
    async def llm(msg, summary, prev, **kwargs):
        return {"intent": "answer", "answer": "",
                "reason": "", "model_status": "unavailable"}
    async def append(*args, **kwargs):
        return "chat-turn"
    calls = []
    class VM:
        async def service_status(self, target, service):
            calls.append((target, service))
            return {"success": True, "target": target,
                    "service": service, "load_state": "loaded",
                    "active_state": "failed", "sub_state": "failed",
                    "result": "timeout"}
    monkeypatch.setattr(identity_module, "VMEdgeMCPClient", lambda: VM())
    monkeypatch.setattr(api, "AsyncSessionLocal", DB)
    monkeypatch.setattr(api, "_scope", scope)
    monkeypatch.setattr(api, "PostgreSQLAuditStore", Audit)
    monkeypatch.setattr(api, "load_decision_brief_for_incident", brief)
    monkeypatch.setattr(api, "llm_plan", llm)
    monkeypatch.setattr(api, "append_turn", append)

    incident_id = UUID("c0a812d6-7d12-4fab-b454-fe5ac4d7c37a")
    status = await api.incident_chat_message(
        incident_id, api.IncidentChatMessage(message="وضعیت سرویس چیه"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert status["kind"] == "tool_result"
    assert status["answer_basis"] == "live_mcp"
    assert "ActiveState=failed" in status["message"]
    assert "target_not_verified" not in status["message"]

    restart = await api.incident_chat_message(
        incident_id, api.IncidentChatMessage(message="ری استارتش کن"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert restart["kind"] == "action_proposal"
    assert restart["proposal"]["action"] == "restart_service"
    assert restart["proposal"]["target"] == "10.248.16.82"
    assert restart["proposal"]["execution_authority"] is False
    assert len(calls) == 2
