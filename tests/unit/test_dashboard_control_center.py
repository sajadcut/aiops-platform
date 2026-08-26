from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_is_single_live_control_center():
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/control-center.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/control-center.css").read_text(encoding="utf-8")

    assert "AIOps Control Center" in html
    assert "MCP Servers" in html
    assert "Incident Intelligence" in html
    assert "Audit & Governance" in html
    assert "/api/v1/dashboard/summary" in js
    assert "/api/v1/dashboard/incidents?limit=100" in js
    assert "/api/v1/health" in js
    assert "/evidence?limit=100" in js
    assert "/lifecycle" in js
    assert "/verification" in js
    assert "/api/v1/agents/catalog" in js
    assert "/api/v1/agents/metrics" in js
    assert "fake" not in js.lower()
    assert "--panel" in css
    assert ".workspace" in css


def test_dashboard_assets_and_agent_route_are_served_by_fastapi():
    source = (ROOT / "apps/api/main.py").read_text(encoding="utf-8")
    assert '@app.get("/dashboard/control-center.css"' in source
    assert '@app.get("/dashboard/control-center.js"' in source
    assert 'return FileResponse(_DASHBOARD_DIR / "index.html")' in source


def test_legacy_agent_url_has_compatibility_redirect_only():
    html = (ROOT / "dashboards/agents.html").read_text(encoding="utf-8")
    assert "location.replace('/dashboard')" in html
    assert "AIOps Agent Intelligence" in html
