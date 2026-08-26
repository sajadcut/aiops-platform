from pathlib import Path


def test_dashboard_ui_contains_live_api_calls():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    assert "/dashboard/control-center.js" in html
    assert "/api/v1/dashboard/summary" in js
    assert "/api/v1/dashboard/incidents" in js
    assert "X-API-Key" in js


def test_dashboard_route_and_api_are_registered():
    source = Path("apps/api/main.py").read_text(encoding="utf-8")
    assert '@app.get("/dashboard"' in source
    assert '@app.get("/dashboard/control-center.css"' in source
    assert '@app.get("/dashboard/control-center.js"' in source
    assert "dashboard_incidents.router" in source
    assert "dashboard.router" in source
