from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.main import app


def test_operator_summary_api_route_is_registered_read_only():
    matches = [route for route in app.routes if getattr(route, "path", None) == "/api/v1/incidents/{incident_id}/operator-summary"]
    assert len(matches) == 1
    assert matches[0].methods == {"GET"}


def test_dashboard_serves_persian_operator_summary_ui_and_structured_api_call():
    client = TestClient(app)

    js = client.get("/dashboard/approval-actions.js")
    assert js.status_code == 200
    assert "/api/v1/incidents/${encodeURIComponent(id)}/operator-summary" in js.text
    assert "خلاصه فارسی رخداد" in js.text
    assert "تأیید شده" in js.text
    assert "محتمل" in js.text
    assert "نامشخص" in js.text
    assert "نیازمند Approval" in js.text
    assert "اجرا موفق" in js.text
    assert "اجرا ناموفق" in js.text
    assert "Verification موفق" in js.text
    assert "Verification ناقص" in js.text
    assert "Decision Support" in js.text

    css = client.get("/dashboard/approval-actions.css")
    assert css.status_code == 200
    assert ".operator-summary-card" in css.text
    assert ".operator-summary-badge.confirmed" in css.text


def test_operator_summary_backend_is_deterministic_and_has_no_execution_path():
    source = Path("apps/operator_summary.py").read_text(encoding="utf-8")
    api_source = Path("apps/api/incident_resources.py").read_text(encoding="utf-8")

    assert "configured_llm_adapter" not in source
    assert "ExecutionService" not in source
    assert "ApprovalService" not in source
    assert "execution_authority\": False" in source
    assert '@router.get("/incidents/{incident_id}/operator-summary")' in api_source
    assert "build_operator_summary" in api_source
