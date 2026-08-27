from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_exposes_real_approval_actions_without_direct_execution():
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/approval-actions.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/approval-actions.css").read_text(encoding="utf-8")

    assert 'approval-actions.css' in html
    assert 'approval-actions.js' in html
    assert '/api/v1/approvals/' in js
    assert '/approve' in js
    assert '/reject' in js
    assert 'rejection reason' in js.lower()
    assert 'JSON.stringify({reason})' in js
    assert 'HIGH-RISK approval' in js
    assert 'This does NOT execute it yet.' in js
    assert '/api/v1/execute' not in js
    assert '.approval-btn.approve' in css
    assert '.approval-btn.reject' in css


def test_fastapi_serves_approval_assets():
    source = (ROOT / "apps/api/main.py").read_text(encoding="utf-8")
    assert '@app.get("/dashboard/approval-actions.css"' in source
    assert '@app.get("/dashboard/approval-actions.js"' in source
