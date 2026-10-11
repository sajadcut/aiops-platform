"""Knowledge Review durable workflow acceptance on a real PostgreSQL schema.

Run only with RUN_DB_KNOWLEDGE_REVIEW_TEST=1 on the disposable CI DB.
Cognia writes are mocked; production Cognia is never contacted by CI.
"""
import os
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from apps.api.main import app
from database import AsyncSessionLocal
from domain.contracts.config import settings
from domain.models import Incident, IncidentStatus, KnowledgeReview, MemoryEntry

pytestmark = [
    pytest.mark.skipif(os.environ.get("RUN_DB_KNOWLEDGE_REVIEW_TEST") != "1",
                       reason="requires isolated PostgreSQL acceptance DB"),
    pytest.mark.asyncio,
]


async def test_verified_memory_human_review_and_cognia_activation(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [1])
    monkeypatch.setattr(settings, "COGNIA_CLIENT_APPLICATION_ID", 2)
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", "ci-knowledge-approval-identity")
    monkeypatch.setattr(settings, "INTERNAL_API_ROLE", "sre")
    from apps.api import knowledge_reviews as api_module

    calls = []
    class FakeCognia:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def register_knowledge(self, **kwargs):
            calls.append(kwargs)
            return {"knowledgeId": 501, "revisionId": 502}
        async def get_knowledge_detail(self, **kwargs):
            return {"activeRevision": {"revisionId": 502}}

    monkeypatch.setattr(api_module, "CogniaClient", FakeCognia)
    incident_id, memory_id = uuid4(), uuid4()
    async with AsyncSessionLocal() as db:
        db.add(Incident(
            id=incident_id, source="ci-knowledge", severity="medium",
            service="gfpapi-ci", status=IncidentStatus.RESOLVED,
            summary="CI verified service recovery"
        ))
        db.add(MemoryEntry(
            id=memory_id, incident_id=incident_id,
            pattern="failed service", verification_result="success",
            root_cause="unknown", root_cause_status="hypothesis",
            memory_outcome_class="successful_recovery",
            service_scope="gfpapi-ci", outcome="service restored",
            reusable_lesson="Verify running status before reuse",
            lifecycle_status="active",
            actual_remediation={"action": "restart_service", "execution_success": True},
            verification={"status": "success", "recovered_signals": ["service_active"]},
        ))
        await db.commit()

    headers = {"X-API-Key": "ci-knowledge-approval-identity"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", headers=headers) as client:
        draft = await client.post("/api/v1/knowledge-reviews/from-memory", json={"memory_id": str(memory_id)})
        assert draft.status_code == 200, draft.text
        row = draft.json()
        assert row["status"] == "pending_review" and row["source_type"] == "incident"
        review_id = row["id"]
        assert calls == []

        repeated = await client.post("/api/v1/knowledge-reviews/from-memory", json={"memory_id": str(memory_id)})
        assert repeated.json()["id"] == review_id
        listed = await client.get("/api/v1/knowledge-reviews", params={"status": "pending_review"})
        assert any(item["id"] == review_id for item in listed.json()["items"])

        forbidden = await client.post(f"/api/v1/knowledge-reviews/{review_id}/publish")
        assert forbidden.status_code == 409 and not calls

        edited = await client.put(f"/api/v1/knowledge-reviews/{review_id}", json={
            "title": "Verified recovery: gfpapi-ci",
            "content": "Approved incident procedure with verified outcome.",
            "expected_revision": 1,
        })
        assert edited.status_code == 200, edited.text
        assert edited.json()["revision"] == 2
        outdated = await client.post(f"/api/v1/knowledge-reviews/{review_id}/approve", json={
            "expected_revision": 1, "reason": "reviewed evidence"
        })
        assert outdated.status_code == 409

        monkeypatch.setattr(settings, "INTERNAL_API_ROLE", "operator")
        operator = await client.post(f"/api/v1/knowledge-reviews/{review_id}/approve", json={
            "expected_revision": 2, "reason": "reviewed evidence"
        })
        assert operator.status_code == 403
        monkeypatch.setattr(settings, "INTERNAL_API_ROLE", "sre")

        approved = await client.post(f"/api/v1/knowledge-reviews/{review_id}/approve", json={
            "expected_revision": 2, "reason": "reviewed incident evidence"
        })
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        published = await client.post(f"/api/v1/knowledge-reviews/{review_id}/publish")
        assert published.status_code == 200, published.text
        assert published.json()["status"] == "submitted"
        assert len(calls) == 1
        assert calls[0]["title"] == "Verified recovery: gfpapi-ci"
        assert calls[0]["content"] == "Approved incident procedure with verified outcome."
        assert calls[0]["idempotency_key"] == f"aiops-review-{review_id}-v2"
        assert calls[0]["scope"] == {"type": "clientApplication", "clientApplicationId": 2}

        replay = await client.post(f"/api/v1/knowledge-reviews/{review_id}/publish")
        assert replay.status_code == 409 and len(calls) == 1
        cannot_edit = await client.put(f"/api/v1/knowledge-reviews/{review_id}", json={
            "title": "Change after publish", "content": "changed", "expected_revision": 2
        })
        assert cannot_edit.status_code == 409
        active = await client.post(f"/api/v1/knowledge-reviews/{review_id}/refresh")
        assert active.status_code == 200 and active.json()["status"] == "published"
        manual = await client.post("/api/v1/knowledge-reviews/manual", json={
            "title": "CI manual runbook", "content": "Validated read-only diagnostic."
        })
        assert manual.status_code == 200
        rejected = await client.post(f"/api/v1/knowledge-reviews/{manual.json()['id']}/reject", json={
            "expected_revision": 1, "reason": "outdated instructions"
        })
        assert rejected.status_code == 200
        assert rejected.json()["status"] == "rejected"
        assert len(calls) == 1

    async with AsyncSessionLocal() as db:
        persisted = (await db.execute(select(KnowledgeReview).where(KnowledgeReview.id == review_id))).scalars().one()
        assert persisted.status == "published"
        assert persisted.reviewed_by == "api-key"
        assert persisted.cognia_knowledge_id == 501
