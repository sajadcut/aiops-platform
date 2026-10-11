from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.main import app


def test_decision_brief_route_is_read_only_and_rbac_scoped():
    matches = [
        route for route in app.routes
        if getattr(route, "path", None) == "/api/v1/incidents/{incident_id}/decision-brief"
    ]
    assert len(matches) == 1
    assert matches[0].methods == {"GET"}
    source = Path("apps/api/incident_resources.py").read_text(encoding="utf-8")
    assert 'dependencies=[Depends(require_permission("read:incident"))]' in source
    assert "build_decision_brief" in source


def test_dashboard_decision_brief_assets_are_served_and_mounted():
    client = TestClient(app)
    html = client.get("/dashboard").text
    js_response = client.get("/dashboard/decision-brief.js")
    css_response = client.get("/dashboard/decision-brief.css")
    assert js_response.status_code == css_response.status_code == 200
    assert '/dashboard/decision-brief.js' in html
    assert '/dashboard/decision-brief.css' in html
    assert 'data-db-lang="fa"' in js_response.text
    assert "decision-brief" in css_response.text
    assert '/api/v1/incidents/' in js_response.text
    assert "openDecisionApproval" not in js_response.text


def test_decision_brief_never_starts_tools_or_retrieval():
    source = Path("apps/decision_brief.py").read_text(encoding="utf-8")
    for forbidden in ("KnowledgeRAGService", "MCPClient(", "ExecutionService", "ApprovalService",
                      "configured_llm_adapter", "execute_runbook"):
        assert forbidden not in source
    js = Path("dashboards/decision-brief.js").read_text(encoding="utf-8")
    assert "/decision-brief" in js
    assert "/resume" not in js
    assert "/approve" not in js
