"""Regression contract for Human-approved Cognia Knowledge Review."""
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from apps.knowledge_review import (
    content_digest, configured_kb, incident_document, memory_is_verified,
    validated_document,
)
from apps.security.rbac import allowed
from domain.contracts.config import settings
from domain.models import KnowledgeReview


ROOT = Path(__file__).resolve().parents[2]


def _memory(**changes):
    fields = dict(
        id=uuid4(), incident_id=uuid4(), service_scope="gfpapi",
        pattern="failed systemd service",
        root_cause="Disk full appears correlated",
        root_cause_status="hypothesis",
        verification_result="success", lifecycle_status="active",
        actual_remediation={
            "action": "restart_service", "execution_success": True,
            "runbook_id": "gfpapi-recovery"
        },
        verification={"status": "success", "recovered_signals": ["service_active"]},
        memory_outcome_class="successful_recovery",
        outcome="verified recovery",
        reusable_lesson="Revalidate current signals and approval before repeat.",
        evidence_provenance={"evidence_count": 1, "evidence_refs": ["vm:status"]},
    )
    fields.update(changes)
    return SimpleNamespace(**fields)


def test_verified_incident_can_be_drafted_but_hypothetical_cause_never_becomes_fact():
    row = _memory()
    assert memory_is_verified(row)
    title, body = incident_document(row)
    assert title == "Verified incident recovery: gfpapi"
    assert "Incident reference: " in body
    assert "Root cause status: hypothesis" in body
    assert "Not independently confirmed" in body
    assert "Disk full appears correlated" not in body
    assert "Safety:" in body
    assert content_digest(title, body) == content_digest(title, body)


@pytest.mark.parametrize("change", [
    {"memory_outcome_class": "failed_recovery"},
    {"verification_result": "failed"},
    {"verification": {"status": "partial"}},
    {"actual_remediation": {"action": "restart_service", "execution_success": False}},
    {"actual_remediation": {"execution_success": True}},
    {"lifecycle_status": "invalidated"},
    {"incident_id": None},
])
def test_unverified_or_negative_experience_cannot_be_mislabeled_as_success(change):
    row = _memory(**change)
    assert not memory_is_verified(row)
    with pytest.raises(HTTPException) as e:
        incident_document(row)
    assert e.value.status_code == 409


def test_verified_cause_may_be_included_but_still_requires_human_review():
    title, body = incident_document(_memory(
        root_cause_status="confirmed", root_cause="Confirmed app log failure"
    ))
    assert "Confirmed app log failure" in body
    assert "Verified incident recovery:" in title


def test_sensitive_content_is_rejected_not_silently_published():
    with pytest.raises(HTTPException, match="knowledge_contains_sensitive_material"):
        validated_document("Credential leaked", "password=not-for-publishing")
    with pytest.raises(HTTPException, match="knowledge_contains_sensitive_material"):
        validated_document("Runbook", "Authorization: Bearer random-token-value")
    with pytest.raises(HTTPException):
        validated_document("", "valid text")
    assert content_digest("t", "a") != content_digest("t", "b")


def test_knowledge_review_is_durable_outbox_not_local_rag():
    columns = KnowledgeReview.__table__.columns
    assert {"approved_hash", "approved_revision", "publish_attempted_at", "cognia_knowledge_id", "memory_id"} <= set(columns.keys())
    assert "embedding" not in columns.keys()
    migration = (ROOT / "database/migrations/versions/k8h9i0j1k2l3_knowledge_review_outbox.py").read_text()
    assert "j7g8h9i0j1k2" in migration
    assert "ux_knowledge_reviews_memory_id" in migration
    assert "knowledge_review_status" in migration


def test_only_sre_can_review_and_publish_knowledge():
    for role in ("viewer", "operator"):
        assert not allowed(role, "knowledge:review")
        assert not allowed(role, "knowledge:publish")
    assert allowed("operator", "knowledge:draft")
    assert allowed("sre", "knowledge:draft")
    assert allowed("sre", "knowledge:review")
    assert allowed("sre", "knowledge:publish")


def test_kb_must_be_configured_not_caller_controlled(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [1])
    assert configured_kb() == 1
    assert configured_kb(1) == 1
    with pytest.raises(HTTPException):
        configured_kb(2)
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [])
    with pytest.raises(HTTPException):
        configured_kb()


def test_publish_path_is_approval_hash_bound_and_does_not_auto_execute():
    source = (ROOT / "apps/api/knowledge_reviews.py").read_text()
    assert 'row.approved_hash != row.content_hash' in source
    assert 'row.approved_revision != row.revision' in source
    assert 'row.status = "approved"' in source
    assert 'row.status = "submitted"' in source
    assert 'row.status = "published"' in source
    assert 'idempotency_key=key' in source
    assert 'memory_is_verified(source)' in source
    assert "execute:approved" not in source
    assert "runbook_executor" not in source
    assert "/api/engine/" not in source


def test_dashboard_review_is_real_ui_and_not_authorization_authority():
    html = (ROOT / "dashboards/index.html").read_text()
    js = (ROOT / "dashboards/knowledge-review.js").read_text()
    assert 'data-view="knowledge"' in html
    assert "Pending Knowledge" in html
    assert "Approve" in js and "Reject" in js and "Save Edit" in js
    assert "/api/v1/knowledge-reviews" in js
    assert "expected_revision" in js
    assert "never" not in js.lower() or "api(" in js
    assert "innerHTML = r.content" not in js
    assert "@app.get(\"/dashboard/knowledge-review.js\"" in (ROOT / "apps/api/main.py").read_text()
