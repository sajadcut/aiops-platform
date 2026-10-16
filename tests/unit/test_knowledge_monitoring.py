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
            {"status": "pending_review", "source_type": "incident", "kb_id": 1, "count": 8,
             "created_in_window": 3, "published_in_window": 0,
             "overdue_review": 2, "stale_publish": 0,
             "overdue_activation": 0, "latest_published": None},
            {"status": "submitted", "source_type": "manual", "kb_id": 7, "count": 2,
             "created_in_window": 2, "published_in_window": 0,
             "overdue_review": 0, "stale_publish": 0,
             "overdue_activation": 1, "latest_published": None},
            {"status": "published", "source_type": "incident", "kb_id": 1, "count": 4,
             "created_in_window": 1, "published_in_window": 3,
             "overdue_review": 0, "stale_publish": 0,
             "overdue_activation": 0, "latest_published": NOW - timedelta(days=1)},
            {"status": "publish_failed", "source_type": "incident", "kb_id": 1, "count": 1,
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
    assert r["by_kb"] == {
        "1": {"total": 13, "published": 4, "submitted": 0, "publish_failed": 1},
        "7": {"total": 2, "published": 0, "submitted": 2, "publish_failed": 0},
    }
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
    assert "byKb[kb].published" in js
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


def _monitoring_test_app():
    """Exercise real HTTP query parsing while isolating the authorization gate."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(api.router, prefix="/api/v1")
    route = next(
        route for route in app.routes
        if getattr(route, "path", "") == "/api/v1/knowledge-reviews/monitoring"
    )
    # Tests must not disable RBAC in production; override only on this
    # disposable in-process test app, using the actual route dependency.
    assert len(route.dependencies) == 1
    app.dependency_overrides[route.dependencies[0].dependency] = lambda: None
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize("days", ["7", "30", "90"])
async def test_monitoring_http_accepts_dashboard_period_strings(monkeypatch, days):
    """Regression: Pydantic v2 numeric Literal rejected all string query values."""
    import httpx

    periods = []

    class Rows:
        def __init__(self, items):
            self.items = items

        def mappings(self):
            return self

        def all(self):
            return self.items

        def one(self):
            return self.items[0]

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, statement, params=None):
            if params and "since" in params:
                periods.append((datetime.now(timezone.utc) - params["since"]).days)
            sql = str(statement)
            if "SELECT (SELECT COUNT(*) FROM incidents)" in sql:
                return Rows([{"incident_total": 4, "incident_with_review": 1}])
            return Rows([])

    async def ready(db, *, operation):
        assert operation == "knowledge_monitoring"

    monkeypatch.setattr(api, "AsyncSessionLocal", Session)
    monkeypatch.setattr(api, "require_database_ready", ready)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_monitoring_test_app()),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/v1/knowledge-reviews/monitoring", params={"days": days})

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["period_days"] == int(days)
    assert payload["coverage"]["percentage"] == 25.0
    assert payload["cognia"]["global_document_total"] is None
    assert len(periods) == 4
    assert all(abs(span - int(days)) <= 1 for span in periods)


@pytest.mark.asyncio
@pytest.mark.parametrize("days", ["1", "14", "91", "not-an-integer"])
async def test_monitoring_http_rejects_unsupported_periods_without_database(monkeypatch, days):
    import httpx

    def unexpected_session():
        raise AssertionError("Invalid report interval must not touch the database")

    monkeypatch.setattr(api, "AsyncSessionLocal", unexpected_session)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_monitoring_test_app()),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/v1/knowledge-reviews/monitoring", params={"days": days})
    assert response.status_code == 422
