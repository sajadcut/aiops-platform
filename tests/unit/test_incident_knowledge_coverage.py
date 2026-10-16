"""Coverage matrix for human Knowledge Review across all incident outcomes."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from apps.knowledge_incident_coverage import (
    coverage_review_id, create_from_incident, incident_coverage_document,
)
from domain.contracts.config import settings
from domain.models import Incident, KnowledgeReview


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("state", [
    "open", "analyzing", "escalated", "resolved", "closed",
])
@pytest.mark.parametrize("scenario", [
    "no_action", "rejected_approval", "blocked_preflight",
    "failed_start", "inconclusive_verification", "verified_recovery",
])
def test_every_incident_outcome_has_truthful_reviewable_document(state, scenario):
    incident = SimpleNamespace(
        id=uuid4(), status=state, source="zabbix", service="nginx",
        severity="High", summary="nginx Service Down",
    )
    evidence = [SimpleNamespace(id=uuid4(), source="vm_mcp", type="event")]
    findings = [SimpleNamespace(agent="vm", statement="Root cause could be config")]
    dossier = {
        "facts": ["وضعیت ثبت‌شدهٔ systemd: inactive"],
        "monitor_recovered": scenario == "verified_recovery",
        "independent_recovery_verified": False,
    }
    title, content = incident_coverage_document(
        incident, evidence=evidence, findings=findings, dossier=dossier,
    )
    assert "nginx" in title and str(incident.id)[:8] in title
    assert state in title
    assert str(incident.id) in content
    assert "فرضیه، نه اثبات مستقل" in content
    assert "انتشار به Cognia تنها پس از تأیید انسانی" in content
    assert ("Recovery معتبر منبع مانیتورینگ" in content) is (
        scenario == "verified_recovery"
    )
    if scenario != "verified_recovery":
        assert "رفع هشدار و سلامت نهایی" in content


def test_unverified_case_with_no_evidence_never_claims_root_cause_or_execution():
    incident = SimpleNamespace(
        id=uuid4(), status="analyzing", source="prometheus",
        service="java-payment", severity="Warning", summary="timeout",
    )
    _, text = incident_coverage_document(incident, evidence=[], findings=[], dossier={})
    assert "شواهد مستقل در نمونهٔ بررسی‌شده موجود نیست" in text
    assert "علت ریشه‌ای نامعلوم است" in text
    assert "اجرای واقعی و راستی‌آزمایی یکسان نیست" in text


def test_one_stable_id_per_incident_across_retries():
    a, b = uuid4(), uuid4()
    assert coverage_review_id(a) == coverage_review_id(a)
    assert coverage_review_id(a) != coverage_review_id(b)


class _Scalar:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows

    def first(self):
        return self.rows[0] if self.rows else None


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return _Scalar(self.rows)


class _DB:
    def __init__(self, incident):
        self.incident = incident
        self.record = None
        self.audit = []
        self.commits = 0

    async def get(self, model, identifier):
        if model is Incident:
            return self.incident
        if model is KnowledgeReview:
            return self.record
        return None

    async def execute(self, query, params=None):
        if params and "event_id" in params:
            self.audit.append(params)
        expression = str(query)
        if "knowledge_reviews" in expression:
            return _Result([self.record] if self.record else [])
        return _Result([])

    def add(self, row):
        self.record = row

    async def flush(self):
        return None

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_coverage_draft_is_idempotent_and_never_publishes(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [1])
    monkeypatch.setattr(settings, "COGNIA_CLIENT_APPLICATION_ID", 2)
    async def dossier(_db, _id):
        return {"facts": [], "monitor_recovered": False}
    monkeypatch.setattr("apps.knowledge_incident_coverage.incident_dossier", dossier)
    incident = SimpleNamespace(
        id=uuid4(), status="open", source="zabbix", service="gfpapi",
        severity="High", summary="systemd service down",
    )
    db = _DB(incident)
    row, outcome = await create_from_incident(db, incident.id)
    assert outcome == "created"
    assert row.source_type == "incident_followup"
    assert row.id == coverage_review_id(incident.id)
    assert row.status == "pending_review"
    assert row.cognia_knowledge_id is None
    assert db.commits == 1 and len(db.audit) == 1
    row.content = "متن ویرایش‌شدهٔ بازبین"
    row.status = "rejected"
    again, outcome = await create_from_incident(db, incident.id)
    assert outcome == "existing"
    assert again is row and row.content == "متن ویرایش‌شدهٔ بازبین"
    assert row.status == "rejected"
    assert db.commits == 1 and len(db.audit) == 1


def test_dashboard_can_sync_old_incidents_and_page_existing_reviews():
    api = (ROOT / "apps/api/knowledge_reviews.py").read_text(encoding="utf-8")
    ui = (ROOT / "dashboards/knowledge-review.js").read_text(encoding="utf-8")
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    runtime = (ROOT / "apps/orchestrator/runtime.py").read_text(encoding="utf-8")
    assert '"/knowledge-reviews/reconcile-incidents"' in api
    assert "async def reconcile_incident_coverage(" in api
    assert "next_offset" in api and "has_more" in api
    assert "offset(offset).limit(limit + 1)" in api
    assert "reconcile-incidents?limit=40&offset=0" in ui
    assert "reconcile-incidents?limit=100&offset=" in ui
    assert "reviewPageCount" in ui and "loadMoreKnowledgeReviews" in ui
    assert 'id="knowledgeLoadMore"' in html
    assert "syncMoreIncidentKnowledge()" in html
    assert "await self._draft_incident_knowledge(incident_id)" in runtime
    assert "draft_incident_best_effort" in runtime
