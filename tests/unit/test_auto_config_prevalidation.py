"""Config repair is proactive, not a way to bypass human approval."""
from __future__ import annotations

import base64
import hashlib

import pytest

from apps.config_change_auto_queue import auto_queue_candidate, auto_queue_prevalidation


def _state():
    original = hashlib.sha256(b"broken").hexdigest()
    fixed = hashlib.sha256(b"repaired").hexdigest()
    return {
        "service_name": "gfpapi",
        "context": {
            "dynamic_investigation": {
                "config_proposal": {
                    "status": "candidate_proposed",
                    "service": "gfpapi",
                    "config_file": "/data/gfp/gfpapi/appsettings.json",
                    "original_sha256": original,
                    "candidate_sha256": fixed,
                    "source_evidence_refs": ["evidence:exact-mcp-validation"],
                    "proposed_change": "quote_unquoted_json_key",
                    "execution_authority": False,
                    "apply_eligible": False,
                },
            },
        },
    }


def test_eligible_microfix_auto_queues_only_a_prevalidation_intent():
    proposal = auto_queue_candidate(_state())
    assert proposal is not None
    assert proposal["proposed_change"] == "quote_unquoted_json_key"
    assert proposal["execution_authority"] is False


@pytest.mark.parametrize("mutation", [
    lambda s: s["context"]["dynamic_investigation"]["config_proposal"].update(
        {"status": "llm_candidate_rejected"}),
    lambda s: s["context"]["dynamic_investigation"]["config_proposal"].update(
        {"candidate_sha256": None}),
    lambda s: s["context"]["dynamic_investigation"]["config_proposal"].update(
        {"source_evidence_refs": []}),
    lambda s: s["context"]["dynamic_investigation"]["config_proposal"].update(
        {"execution_authority": True}),
    lambda s: s["context"]["dynamic_investigation"]["config_proposal"].update(
        {"proposed_change": "arbitrary_shell"}),
    lambda s: s.update({"approval": {"approval_id": "exists"}}),
])
def test_unverified_candidate_never_enters_the_auto_queue(mutation):
    state = _state()
    mutation(state)
    assert auto_queue_candidate(state) is None


@pytest.mark.asyncio
async def test_without_candidate_no_database_or_validator_is_called():
    class DB:
        async def get(self, *args, **kwargs):
            raise AssertionError("no candidate: no database read")
    assert await auto_queue_prevalidation(DB(), "11111111-1111-4111-8111-111111111111", {}) == {
        "status": "no_verified_candidate", "reason": "no_config_proposal",
        "approval_id": None, "production_write_performed": False,
    }


@pytest.mark.asyncio
async def test_mcp_review_prefers_broken_appsettings_over_first_healthy_json(monkeypatch):
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = object.__new__(SSHVMConnector)
    monkeypatch.setattr(connector, "_validate_service", lambda service: None)

    async def validator(target, service):
        return {"success": True, "supported": False, "valid": None}

    async def discovery(target, service):
        return {"status": "verified", "files": [
            {"path": "/data/gfp/gfpapi/alpha.json", "verified_exists": True},
            {"path": "/data/gfp/gfpapi/appsettings.json", "verified_exists": True},
        ]}

    async def read(target, command):
        if "/alpha.json" in command:
            value = '{"status":"ok"}'
        else:
            value = '{"enabled":true, invalid-key!:1}'
        return {"success": True,
                "stdout": base64.b64encode(value.encode()).decode()}

    monkeypatch.setattr(connector, "config_validate", validator)
    monkeypatch.setattr(connector, "service_config_discovery", discovery)
    monkeypatch.setattr(connector, "_run", read)
    result = await connector.service_config_review("10.248.16.82", "gfpapi")
    assert result["success"] is True
    assert result["config_file"] == "/data/gfp/gfpapi/appsettings.json"
    assert result["validation_status"] == "FORMAT_INVALID"
    assert result["status"] != "candidate_proposed"
    assert result["candidate_hash"] is None
    assert result["execution_authority"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("recover_stopped_service", [False, True])
async def test_valid_microfix_auto_creates_nonapprovable_request_and_only_validates(
    monkeypatch, recover_stopped_service,
):
    """The automated branch can queue/stage, not approve or apply a file."""
    import apps.config_change_auto_queue as mod
    from types import SimpleNamespace

    state = _state()
    seen = []
    class DB:
        async def get(self, cls, key):
            return SimpleNamespace(service="gfpapi", context={})
        async def execute(self, statement, parameters):
            return SimpleNamespace(scalar_one_or_none=lambda: None)
    class Audit:
        def __init__(self, session):
            pass
        async def list(self, incident_id, limit):
            return []
        async def append(self, record):
            seen.append(("audit", record["status"]))
    class Approvals:
        def __init__(self, session):
            pass
        async def save_validation_request(self, record):
            seen.append(("queue", record))
            return {"approval_id": record["approval_id"], "status": "pending_validation"}
    async def stage(approval_id, *, actor):
        seen.append(("stage", actor))
        return {"status": "pending", "validation": "passed"}
    monkeypatch.setattr(mod, "PostgreSQLAuditStore", Audit)
    monkeypatch.setattr(mod, "PostgreSQLApprovalStore", Approvals)
    monkeypatch.setattr(mod, "incident_vm_context", lambda *a: {})
    monkeypatch.setattr(mod, "vm_binding_diagnostic",
                        lambda *a: {"candidate": "10.248.16.82"})
    monkeypatch.setattr(mod, "validate_config_ticket", stage)
    async def verified_recovery_scope(*, target, service):
        assert target == "10.248.16.82" and service == "gfpapi"
        return recover_stopped_service
    monkeypatch.setattr(mod, "_verified_service_start_scope",
                        verified_recovery_scope)
    result = await mod.auto_queue_prevalidation(
        DB(), "11111111-1111-4111-8111-111111111111", state,
    )
    assert result["status"] == "pending"
    assert [record[0] for record in seen] == ["queue", "audit", "stage"]
    record = seen[0][1]
    assert record["action"] == "apply_configuration_change"
    assert record["metadata"]["start_service_after_apply"] is recover_stopped_service
    assert record["metadata"]["isolated_validation"] is False
    assert record["metadata"]["production_write_performed"] is False
    assert record["metadata"]["automated_prevalidation"] is True
    assert seen[-1] == ("stage", "aiops-auto-prevalidation")


@pytest.mark.asyncio
@pytest.mark.parametrize("state,scope", [
    ({"success": True, "target": "192.0.2.10", "service": "nginx",
      "load_state": "loaded", "active_state": "failed", "sub_state": "failed"}, True),
    ({"success": True, "target": "192.0.2.10", "service": "nginx",
      "load_state": "loaded", "active_state": "inactive", "sub_state": "dead"}, True),
    ({"success": True, "target": "192.0.2.10", "service": "nginx",
      "load_state": "loaded", "active_state": "active", "sub_state": "running"}, False),
    ({"success": True, "target": "192.0.2.10", "service": "nginx",
      "load_state": "loaded", "active_state": "activating", "sub_state": "auto-restart"}, False),
    ({"success": True, "target": "192.0.2.99", "service": "nginx",
      "load_state": "loaded", "active_state": "failed", "sub_state": "failed"}, False),
    ({"success": True, "target": "192.0.2.10", "service": "other",
      "load_state": "loaded", "active_state": "failed", "sub_state": "failed"}, False),
    ({"success": False, "target": "192.0.2.10", "service": "nginx",
      "load_state": "loaded", "active_state": "failed", "sub_state": "failed"}, False),
])
async def test_live_recovery_scope_matches_only_verified_stopped_bound_unit(
    monkeypatch, state, scope,
):
    from apps import config_change_auto_queue as module
    class FakeClient:
        async def service_status(self, target, service):
            assert target == "192.0.2.10"
            assert service == "nginx"
            return state
    monkeypatch.setattr(module, "VMEdgeMCPClient", FakeClient)
    got = await module._verified_service_start_scope(
        target="192.0.2.10", service="nginx",
    )
    assert got is scope


@pytest.mark.asyncio
async def test_recovery_scope_transport_failure_never_grants_start(monkeypatch):
    from apps import config_change_auto_queue as module
    class BrokenClient:
        async def service_status(self, target, service):
            raise RuntimeError("gateway unavailable")
    monkeypatch.setattr(module, "VMEdgeMCPClient", BrokenClient)
    assert await module._verified_service_start_scope(
        target="192.0.2.10", service="nginx",
    ) is False
