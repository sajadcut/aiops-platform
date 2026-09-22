from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

import apps.api.remediation as api
from apps.execution_service import ExecutionResult


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Store:
    consume_calls = 0
    cancel_calls = 0

    def __init__(self, _db):
        pass

    async def get(self, approval_id):
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "start_service",
            "status": "approved",
            "metadata": {
                "service": "nginx",
                "target": "10.100.6.199",
                "target_port": 86,
                "runbook_id": "vm-service-recovery",
                "runbook_version": "1.1",
            },
        }

    async def cancel(self, approval_id, *, reason, metadata_patch=None):
        self.__class__.cancel_calls += 1
        return {
            "approval_id": approval_id,
            "status": "rejected",
            "metadata": {
                "cancellation_reason": reason,
                **dict(metadata_patch or {}),
            },
        }

    async def consume(self, approval_id):
        self.__class__.consume_calls += 1
        return {
            "approval_id": approval_id,
            "status": "consumed",
        }


class _IncidentRepo:
    calls = []

    def __init__(self, _db):
        pass

    async def record_operational_outcome(self, incident_id, **kwargs):
        self.__class__.calls.append((incident_id, kwargs))
        return "resolved" if kwargs.get("verified") else "escalated"

    async def commit(self):
        return None


class _Registry:
    def __init__(self, _root):
        pass

    def get(self, runbook_id):
        return {
            "id": runbook_id,
            "version": "1.1",
            "verification": {
                "checks": [
                    {
                        "state": "service_active",
                        "direction": "equals",
                        "expected": True,
                    },
                    {
                        "state": "port_listening",
                        "direction": "equals",
                        "expected": True,
                    },
                ]
            },
        }


def _identity():
    return SimpleNamespace(subject="sre-user")


def test_remediation_request_rejects_action_without_executable_runbook_contract():
    with pytest.raises(ValidationError):
        api.RemediationRequest(
            target="10.100.6.199",
            service="nginx",
            action="reload_service",
        )


@pytest.mark.asyncio
async def test_remediation_preflight_blocks_before_approval_consume(monkeypatch):
    _Store.consume_calls = 0
    _Store.cancel_calls = 0
    execute_calls = []

    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _Store)
    monkeypatch.setattr(api, "assert_bound", lambda *args, **kwargs: None)

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(api, "_audit_durable", no_audit)

    async def snapshot(**kwargs):
        return {
            "supported": True,
            "read_success": True,
            "error": None,
            "evidence": [],
            "context": {"live_evidence": {"evidence": []}},
        }

    monkeypatch.setattr(api.RunbookRuntimeGuard, "collect_snapshot", snapshot)
    monkeypatch.setattr(
        api.RunbookRuntimeGuard,
        "preflight",
        lambda **kwargs: {
            "safe_to_execute": False,
            "reason": "service_no_longer_unhealthy",
            "evidence_refs": ["svc"],
        },
    )

    async def execute(_request):
        execute_calls.append(_request)
        raise AssertionError("execution must not run after failed preflight")

    monkeypatch.setattr(api.ExecutionService, "execute", execute)

    with pytest.raises(HTTPException) as exc:
        await api.execute_approved_remediation(
            "approval-1",
            identity=_identity(),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == (
        "remediation_precondition_failed:service_no_longer_unhealthy"
    )
    assert _Store.consume_calls == 0
    assert _Store.cancel_calls == 1
    assert execute_calls == []


@pytest.mark.asyncio
async def test_remediation_success_requires_post_action_verification(monkeypatch):
    _Store.consume_calls = 0
    snapshots = []

    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _Store)
    monkeypatch.setattr(api, "assert_bound", lambda *args, **kwargs: None)
    monkeypatch.setattr(api, "RunbookRegistry", _Registry)
    _IncidentRepo.calls = []
    monkeypatch.setattr(api, "IncidentRepository", _IncidentRepo)

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(api, "_audit_durable", no_audit)

    async def snapshot(**kwargs):
        snapshots.append(kwargs["phase"])
        return {
            "supported": True,
            "read_success": True,
            "error": None,
            "evidence": [{"reference": f"{kwargs['phase']}-svc"}],
            "context": {
                "live_evidence": {
                    "evidence": [{"reference": f"{kwargs['phase']}-svc"}]
                }
            },
        }

    monkeypatch.setattr(api.RunbookRuntimeGuard, "collect_snapshot", snapshot)
    monkeypatch.setattr(
        api.RunbookRuntimeGuard,
        "preflight",
        lambda **kwargs: {
            "safe_to_execute": True,
            "reason": "fresh_execution_preconditions_satisfied",
            "evidence_refs": ["pre-svc"],
        },
    )

    verification = SimpleNamespace(
        status=SimpleNamespace(value="success"),
        required_objectives_met=True,
        model_dump=lambda mode=None: {
            "status": "success",
            "required_objectives_met": True,
            "evidence_refs": ["post-svc"],
        },
    )

    async def verify(**kwargs):
        return verification

    monkeypatch.setattr(api.RunbookRuntimeGuard, "verify", verify)

    memory_calls = []

    async def record_memory(_db, **kwargs):
        memory_calls.append(kwargs)
        return "memory-remediation-1"

    monkeypatch.setattr(api, "record_runbook_outcome", record_memory)

    async def execute(request):
        return ExecutionResult(
            success=True,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            result={"success": True},
            approval_id=request.approval_id,
        )

    monkeypatch.setattr(api.ExecutionService, "execute", execute)

    result = await api.execute_approved_remediation(
        "approval-1",
        identity=_identity(),
    )

    assert _Store.consume_calls == 1
    assert snapshots == ["pre", "post"]
    assert result["success"] is True
    assert result["verified"] is True
    assert result["verification"]["status"] == "success"
    assert result["precondition"]["safe_to_execute"] is True
    assert result["operational_memory_writeback"]["memory_id"] == "memory-remediation-1"
    assert result["incident_status"] == "resolved"
    assert len(_IncidentRepo.calls) == 1
    assert _IncidentRepo.calls[0][1]["verified"] is True
    assert _IncidentRepo.calls[0][1]["memory_id"] == "memory-remediation-1"
    assert len(memory_calls) == 1
    assert memory_calls[0]["incident_id"] == "incident-1"
    assert memory_calls[0]["action"] == "start_service"


class _ConsumedStore(_Store):
    dry_run = False

    async def get(self, approval_id):
        return {
            "approval_id": approval_id,
            "incident_id": "33333333-3333-3333-3333-333333333333",
            "action": "start_service",
            "status": "consumed",
            "metadata": {
                "service": "nginx",
                "target": "10.100.6.199",
                "target_port": 86,
                "runbook_id": "vm-service-recovery",
                "runbook_version": "1.1",
                "dry_run": self.__class__.dry_run,
            },
        }


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _VerificationSession(_Session):
    rows = []

    async def execute(self, _statement):
        return _Rows(self.__class__.rows)


@pytest.mark.asyncio
async def test_manual_verification_rejects_dry_run(monkeypatch):
    _ConsumedStore.dry_run = True
    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _VerificationSession())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _ConsumedStore)

    with pytest.raises(HTTPException) as exc:
        await api.verify_remediation(
            "approval-1",
            api.VMVerificationRequest(),
            identity=_identity(),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "dry_run_has_no_executed_recovery_to_verify"
    _ConsumedStore.dry_run = False


@pytest.mark.asyncio
async def test_manual_verification_uses_runbook_objectives_and_validates_matching_memory(monkeypatch):
    from uuid import UUID

    _ConsumedStore.dry_run = False
    memory_row = SimpleNamespace(
        id=UUID("44444444-4444-4444-4444-444444444444"),
        actual_remediation={"approval_id": "approval-1"},
    )
    _VerificationSession.rows = [memory_row]

    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _VerificationSession())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _ConsumedStore)
    monkeypatch.setattr(api, "RunbookRegistry", _Registry)

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(api, "_audit_durable", no_audit)

    snapshot_calls = []

    async def snapshot(**kwargs):
        snapshot_calls.append(kwargs)
        return {
            "supported": True,
            "read_success": True,
            "error": None,
            "evidence": [{"reference": "manual-post"}],
            "context": {
                "live_evidence": {
                    "evidence": [
                        {
                            "reference": "manual-post-service",
                            "raw_data": {
                                "diagnostic": "service_status",
                                "active_state": "active",
                            },
                        },
                        {
                            "reference": "manual-post-listener",
                            "raw_data": {
                                "diagnostic": "port_listener_status",
                                "listening": True,
                            },
                        },
                    ]
                }
            },
        }

    monkeypatch.setattr(api.RunbookRuntimeGuard, "collect_snapshot", snapshot)

    verification = SimpleNamespace(
        status=SimpleNamespace(value="success"),
        required_objectives_met=True,
        model_dump=lambda mode=None: {
            "status": "success",
            "required_objectives_met": True,
            "objective_results": [
                {"target": "service_active", "passed": True},
                {"target": "port_listening", "passed": True},
            ],
        },
    )

    async def verify(**kwargs):
        assert kwargs["before_context"] == {}
        assert kwargs["after_context"]["live_evidence"]["evidence"]
        return verification

    monkeypatch.setattr(api.RunbookRuntimeGuard, "verify", verify)

    validated = []

    class _Memory:
        def __init__(self, _db):
            pass

        async def mark_validated(self, entry_id):
            validated.append(str(entry_id))
            return True

    monkeypatch.setattr(api, "OperationalMemoryService", _Memory)
    _IncidentRepo.calls = []
    monkeypatch.setattr(api, "IncidentRepository", _IncidentRepo)

    result = await api.verify_remediation(
        "approval-1",
        api.VMVerificationRequest(target="10.100.6.199"),
        identity=_identity(),
    )

    assert result["verified"] is True
    assert result["status"] == "verified"
    assert result["verification_status"] == "success"
    assert result["memory_id"] == "44444444-4444-4444-4444-444444444444"
    assert result["memory_validated"] is True
    assert result["incident_status"] == "resolved"
    assert validated == ["44444444-4444-4444-4444-444444444444"]
    assert len(_IncidentRepo.calls) == 1
    assert _IncidentRepo.calls[0][1]["verified"] is True
    assert snapshot_calls[0]["phase"] == "manual_verify"
    assert snapshot_calls[0]["parameters"] == {
        "service": "nginx",
        "target_port": 86,
    }


@pytest.mark.asyncio
async def test_manual_failed_verification_does_not_revalidate_memory(monkeypatch):
    from uuid import UUID

    _ConsumedStore.dry_run = False
    _VerificationSession.rows = [
        SimpleNamespace(
            id=UUID("55555555-5555-5555-5555-555555555555"),
            actual_remediation={"approval_id": "approval-1"},
        )
    ]
    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _VerificationSession())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _ConsumedStore)
    monkeypatch.setattr(api, "RunbookRegistry", _Registry)

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(api, "_audit_durable", no_audit)

    async def snapshot(**kwargs):
        return {
            "supported": True,
            "read_success": True,
            "error": None,
            "evidence": [],
            "context": {"live_evidence": {"evidence": []}},
        }

    monkeypatch.setattr(api.RunbookRuntimeGuard, "collect_snapshot", snapshot)

    verification = SimpleNamespace(
        status=SimpleNamespace(value="failed"),
        required_objectives_met=False,
        model_dump=lambda mode=None: {
            "status": "failed",
            "required_objectives_met": False,
        },
    )

    async def verify(**kwargs):
        return verification

    monkeypatch.setattr(api.RunbookRuntimeGuard, "verify", verify)

    validated = []

    class _Memory:
        def __init__(self, _db):
            pass

        async def mark_validated(self, entry_id):
            validated.append(str(entry_id))
            return True

    monkeypatch.setattr(api, "OperationalMemoryService", _Memory)
    _IncidentRepo.calls = []
    monkeypatch.setattr(api, "IncidentRepository", _IncidentRepo)

    result = await api.verify_remediation(
        "approval-1",
        api.VMVerificationRequest(),
        identity=_identity(),
    )

    assert result["verified"] is False
    assert result["status"] == "not_recovered"
    assert result["memory_id"] == "55555555-5555-5555-5555-555555555555"
    assert result["memory_validated"] is False
    assert result["incident_status"] == "escalated"
    assert validated == []
    assert len(_IncidentRepo.calls) == 1
    assert _IncidentRepo.calls[0][1]["verified"] is False
