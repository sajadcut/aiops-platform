"""Durable, read-only Knowledge/RAG monitoring contracts."""
from datetime import datetime, date, timedelta, timezone

import pytest

from apps.api import knowledge_reviews as api


NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


def test_monitoring_separates_review_outbox_from_cognia_inventory(monkeypatch):
    from domain.contracts.config import settings

    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [1, 7])
    payload = api._knowledge_monitoring_projection(
        [
            {"status": "pending_review", "source_type": "incident", "count": 8,
             "created_in_window": 3, "published_in_window": 0,
             "overdue_review": 2, "stale_publish": 0,
             "overdue_activation": 0, "latest_published": None},
            {"status": "submitted", "source_type": "manual", "count": 2,
             "created_in_window": 2, "published_in_window": 0,
             "overdue_review": 0, "stale_publish": 0,
             "overdue_activation": 1, "latest_published": None},
            {"status": "published", "source_type": "incident", "count": 4,
             "created_in_window": 1, "published_in_window": 3,
             "overdue_review": 0, "stale_publish": 0,
             "overdue_activation": 0, "latest_published": NOW - timedelta(days=1)},
            {"status": "publish_failed", "source_type": "incident", "count": 1,
             "created_in_window": 1, "published_in_window": 0,
             "overdue_review": 0, "stale_publish": 0,
             "overdue_activation": 0, "latest_published": None},
        ],
        [{"day": date(2026, 10, 16), "count": 2}],
        [{"day": date(2026, 10, 15), "count": 1}],
        [
            {"status": "available", "calls": 7, "returned_items": 12,
             "last_attempt": NOW - timedelta(minutes=3)},
            {"status": "empty", "calls": 2, "returned_items": 0,
             "last_attempt": NOW - timedelta(minutes=4)},
            {"status": "transport_unavailable", "calls": 1, "returned_items": 0,
             "last_attempt": NOW - timedelta(minutes=2)},
        ],
        {"incident_total": 20, "incident_with_review": 12},
        days=30, now=NOW,
    )
    r = payload["reviews"]
    assert r["total"] == 15
    assert r["by_status"]["submitted"] == 2
    assert r["by_status"]["published"] == 4
    assert r["by_status"]["pending_review"] == 8
    assert r["by_status"]["publish_failed"] == 1
    assert r["review_overdue_24h"] == 2
    assert r["activation_overdue_24h"] == 1
    assert r["created_in_period"] == 7
    assert r["published_in_period"] == 3
    assert r["latest_published_at"] is not None
    assert r["by_source"] == {"incident": 13, "manual": 2}
    assert len(r["daily_last_14_days"]) == 14
    assert r["daily_last_14_days"][-1]["day"] == "2026-10-16"
    assert r["daily_last_14_days"][-1]["drafted"] == 2
    assert r["daily_last_14_days"][-2]["published"] == 1
    assert payload["coverage"]["percentage"] == 60
    assert payload["retrieval"]["observed_calls"] == 10
    assert payload["retrieval"]["returned_items_total"] == 12
    assert payload["retrieval"]["by_status"]["transport_unavailable"] == 1
    assert payload["retrieval"]["coverage_complete"] is False
    assert payload["retrieval"]["context_relevance"] is None
    assert payload["retrieval"]["groundedness"] is None
    assert payload["retrieval"]["p95_latency_ms"] is None
    assert payload["cognia"]["configured_kb_ids"] == [1, 7]
    assert payload["cognia"]["global_document_total"] is None


def test_empty_monitoring_does_not_invent_retrieval_quality_or_coverage():
    payload = api._knowledge_monitoring_projection(
        [], [], [], [], {"incident_total": 0, "incident_with_review": 0},
        days=7, now=NOW,
    )
    assert payload["reviews"]["total"] == 0
    assert payload["retrieval"]["observed_calls"] == 0
    assert payload["coverage"]["percentage"] is None
    assert payload["cognia"]["global_document_total"] is None


@pytest.mark.asyncio
async def test_monitoring_queries_only_aggregated_durable_sources(monkeypatch):
    calls = []

    class Result:
        def __init__(self, data):
            self.data = data

        def mappings(self):
            return self

        def all(self):
            return self.data

        def one(self):
            return self.data[0]

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, statement, params=None):
            sql = str(statement)
            calls.append((sql, params))
            if "SELECT (SELECT COUNT(*) FROM incidents)" in sql:
                return Result([{"incident_total": 3, "incident_with_review": 2}])
            return Result([])

    async def ready(session, *, operation):
        assert operation == "knowledge_monitoring"

    monkeypatch.setattr(api, "AsyncSessionLocal", Session)
    monkeypatch.setattr(api, "require_database_ready", ready)

    result = await api.knowledge_monitoring(days=30)
    assert result["coverage"]["percentage"] == 66.7
    assert result["reviews"]["total"] == 0
    assert len(calls) == 5
    assert all("SELECT" in query and "content" not in query.lower()
               for query, _ in calls)
    assert all("FROM knowledge_reviews" in query or
               "FROM audit_events" in query or "FROM incidents" in query
               for query, _ in calls)
    assert result["cognia"]["global_document_total"] is None


def test_monitoring_endpoint_order_and_safe_ui_contract():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    api_source = (root / "apps/api/knowledge_reviews.py").read_text(encoding="utf-8")
    html = (root / "dashboards/index.html").read_text(encoding="utf-8")
    js = (root / "dashboards/knowledge-review.js").read_text(encoding="utf-8")
    css = (root / "dashboards/knowledge-review.css").read_text(encoding="utf-8")
    assert api_source.index('"/knowledge-reviews/monitoring"') < api_source.index(
        '"/knowledge-reviews/{review_id}"'
    )
    assert 'Depends(require_permission("read:incident"))' in api_source
    assert "knowledgeMonitorKpis" in html
    assert "knowledgeMonitorRetrieval" in html
    assert "knowledgeMonitorCognia" in html
    assert "knowledgeMonitorTrend" in html
    assert "/api/v1/knowledge-reviews/monitoring?days=" in js
    assert "loadKnowledgeMonitoring" in js
    assert "اندازه‌گیری نشده" in js
    assert "global_document_total" in api_source
    assert "knowledge-monitor-kpis" in css
    assert "knowledge-review.js?v=20261016-rag-monitor1" in html
    # Governance cannot be weakened to implement reporting.
    assert 'row.approved_hash != row.content_hash' in api_source
    assert "row.status = \"submitted\"" in api_source
    assert "row.status = \"published\"" in api_source
