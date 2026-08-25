from pathlib import Path


def test_dashboard_ui_contains_live_api_calls():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    assert "/dashboard/summary" in html
    assert "/dashboard/incidents" in html
    assert "const API='/api/v1'" in html
    assert "X-API-Key" in html


def test_dashboard_route_and_api_are_registered():
    source = Path("apps/api/main.py").read_text(encoding="utf-8")
    assert '@app.get("/dashboard"' in source
    assert "dashboard_incidents.router" in source
    assert "dashboard.router" in source
