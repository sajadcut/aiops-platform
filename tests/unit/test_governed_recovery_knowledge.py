"""Regression: a real approved gfpapi restart must reach HUMAN Knowledge Review.

Incomplete port verification is a cautionary historical record, not a claim
that the incident or its root cause was resolved.
"""
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from apps.knowledge_review import (
    governed_recovery_document, recovery_review_id,
    create_from_governed_service_recovery,
)
from domain.contracts.config import settings
from domain.models import KnowledgeReview, Incident


def _fixture():
    incident_id = uuid4()
    approval_id = str(uuid4())
    incident = SimpleNamespace(id=incident_id, service="gfpapi", status="escalated")
    event = {
        "event_type": "remediation_executed", "action": "restart_service",
        "metadata": {
            "approval_id": approval_id, "memory_id": str(uuid4()),
            "result": {
                "success": True, "tool_name": "ssh_vm",
                "target": "10.248.16.82", "action": "restart_service",
                "execution_blocked": False,
                "result": {"success": True, "service": "gfpapi"},
            },
            "precondition": {
                "safe_to_execute": True, "action": "restart_service",
                "target": "10.248.16.82", "service": "gfpapi",
            },
            "verification": {
                "status": "inconclusive", "required_objectives_met": False,
                "evidence_refs": [
                    f"runbook:pre:{incident_id}:service_status:10.248.16.82:gfpapi",
                    f"runbook:post:{incident_id}:service_status:10.248.16.82:gfpapi",
                ],
                "objective_results": [
                    {"target": "service_active", "actual": 1.0,
                     "passed": True},
                    {"target": "port_listening", "actual": None,
                     "passed": False,
                     "reason": "post_execution_objective_evidence_missing"},
                ],
            },
        },
    }
    return incident, event, approval_id


def test_gfpapi_inconclusive_restart_generates_truthful_pending_review_content():
    incident, event, approval_id = _fixture()
    result = governed_recovery_document(incident, event, approval_id)
    assert result is not None
    title, body = result
    assert "gfpapi" in title and "بازبینی انسانی" in title
    assert "راستی‌آزمایی ناقص" in title
    assert "port_listening" not in body
    assert "گوش‌دادن روی پورت" in body
    assert "شاهد کافی ثبت نشده" in body
    assert "علت ریشه‌ای: با این اجرای Restart به‌تنهایی تأیید نشده" in body
    assert "رفع قطعی رخداد نیست" in body
    assert "Cognia" in body
    assert "10.248.16.82" in body
    assert "SECRETS" not in body


@pytest.mark.parametrize("change", [
    {"metadata.result.success": False},
    {"metadata.result.action": "stop_service"},
    {"metadata.precondition.safe_to_execute": False},
    {"metadata.precondition.target": "1.2.3.4"},
    {"metadata.precondition.service": "nginx"},
    {"metadata.result.execution_blocked": True},
    {"metadata.verification.objective_results": []},
    {"metadata.verification.evidence_refs": []},
    {"metadata.verification.status": "unknown"},
])
def test_untrusted_or_unverified_action_never_creates_a_recovery_draft(change):
    incident, event, approval_id = _fixture()
    import copy
    event = copy.deepcopy(event)
    for path, value in change.items():
        current = event
        keys = path.split(".")
        for key in keys[:-1]:
            current = current[key]
        current[keys[-1]] = value
    assert governed_recovery_document(incident, event, approval_id) is None


def test_verifier_can_mark_genuine_success_without_inventing_root_cause():
    incident, event, approval_id = _fixture()
    check = event["metadata"]["verification"]
    check["status"] = "success"
    check["required_objectives_met"] = True
    check["objective_results"][1].update(actual=True, passed=True)
    title, content = governed_recovery_document(incident, event, approval_id)
    assert "راستی‌آزمایی مستقل کامل" in title
    assert "همهٔ اهداف الزامی تأیید شدند: بله" in content
    assert "علت ریشه‌ای: با این اجرای Restart به‌تنهایی تأیید نشده" in content


def test_deterministic_review_id_survives_refresh_and_reviewer_edits():
    incident, event, approval_id = _fixture()
    assert recovery_review_id(incident.id, approval_id) == recovery_review_id(incident.id, approval_id)
    assert recovery_review_id(incident.id, approval_id) != recovery_review_id(incident.id, str(uuid4()))


@pytest.mark.asyncio
async def test_audit_reconciliation_persists_draft_but_does_not_call_cognia(monkeypatch):
    incident, event, approval_id = _fixture()
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [1])
    monkeypatch.setattr(settings, "COGNIA_CLIENT_APPLICATION_ID", 33)

    class ScalarResult:
        def __init__(self, rows=None): self.rows = rows or []
        def mappings(self): return self
        def all(self): return self.rows

    class DB:
        def __init__(self):
            self.record = None
            self.locked = False
            self.audited = False
            self.committed = 0
        async def execute(self, query, values):
            if "pg_advisory_xact_lock" in str(query):
                self.locked = True
            if "knowledge_drafted" in str(query):
                assert self.locked
                assert values["actor"] == "system:governed-recovery"
                self.audited = True
            return ScalarResult()
        async def get(self, model, key):
            if model is Incident:
                assert key == incident.id
                return incident
            if model is KnowledgeReview:
                return self.record
            raise AssertionError("unexpected model")
        def add(self, record):
            assert self.locked
            self.record = record
        async def flush(self):
            assert self.record.status == "pending_review"
        async def commit(self): self.committed += 1
        async def refresh(self, row): pass

    from apps.audit_service import postgres as audit_module
    class Audit:
        def __init__(self, db): pass
        async def list(self, incident_id, limit=250):
            assert str(incident.id) == incident_id
            return [event]
    monkeypatch.setattr(audit_module, "PostgreSQLAuditStore", Audit)

    db = DB()
    record = await create_from_governed_service_recovery(
        db, incident_id=incident.id, approval_id=approval_id)
    assert record.status == "pending_review"
    assert record.source_type == "incident_followup"
    assert record.created_by == "system:governed-recovery"
    assert db.audited and db.committed == 1
    assert record.cognia_knowledge_id is None
    assert record.id == recovery_review_id(incident.id, approval_id)
    again = await create_from_governed_service_recovery(
        db, incident_id=incident.id, approval_id=approval_id)
    assert again is record and db.committed == 1


@pytest.mark.asyncio
async def test_reconcile_rejects_unaudited_attempt(monkeypatch):
    incident, event, approval_id = _fixture()
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [1])
    monkeypatch.setattr(settings, "COGNIA_CLIENT_APPLICATION_ID", 33)
    from apps.audit_service import postgres as audit_module
    class Audit:
        def __init__(self, db): pass
        async def list(self, incident_id, limit=250): return []
    monkeypatch.setattr(audit_module, "PostgreSQLAuditStore", Audit)
    class DB:
        async def execute(self, *_): return None
        async def get(self, model, _):
            return incident if model is Incident else None
    assert await create_from_governed_service_recovery(
        DB(), incident_id=incident.id, approval_id=approval_id) is None



@pytest.mark.asyncio
async def test_reconcile_recent_backfills_old_gfpapi_from_audit_without_publishing(monkeypatch):
    from unittest.mock import AsyncMock
    from apps.api import knowledge_reviews as api
    from apps import knowledge_review as review_module

    incident, event, approval_id = _fixture()

    class Result:
        def mappings(self): return self
        def all(self):
            return [
                {"incident_id": incident.id, "approval_id": approval_id},
                {"incident_id": incident.id, "approval_id": approval_id},
            ]

    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False
        async def execute(self, query, params):
            assert "remediation_executed" in str(query)
            assert params["limit"] == 30
            return Result()

    monkeypatch.setattr(api, "AsyncSessionLocal", DB)
    ready = AsyncMock()
    create = AsyncMock(return_value=SimpleNamespace(id=uuid4()))
    monkeypatch.setattr(api, "require_database_ready", ready)
    monkeypatch.setattr(review_module, "create_from_governed_service_recovery", create)
    result = await api.reconcile_recent_recovery_reviews(limit=30)
    assert result["status"] == "completed"
    assert result["matched"] == 1 and result["skipped"] == 1
    assert len(result["items"]) == 1
    assert create.await_count == 1
    assert create.await_args.kwargs["incident_id"] == incident.id
    assert create.await_args.kwargs["approval_id"] == approval_id
    assert result["published_to_cognia"] is False
    assert result["requires_human_review"] is True


def test_knowledge_review_ui_reconciles_once_and_never_auto_publishes():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] /
            "dashboards" / "knowledge-review.js").read_text(encoding="utf-8")
    assert "let recoveryReconciled = false" in text
    assert "if (!recoveryReconciled)" in text
    assert "recoveryReconciled = true" in text
    assert "/api/v1/knowledge-reviews/reconcile-recent" in text
    assert "method:'POST'" in text
    # The queue is now paginated: receiving only the newest 100 used to hide
    # legitimate older drafts, even after durable recovery reconciliation.
    assert "const result = await api('/api/v1/knowledge-reviews?limit=100&offset='+(page*100))" in text
    assert "reviewPageCount" in text
    assert "reviewHasMore = result.has_more === true;" in text
    assert "if (op === 'approve')" in text
