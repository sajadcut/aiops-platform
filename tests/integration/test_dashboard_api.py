from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.main import app


def test_dashboard_ui_contains_live_api_calls():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    assert 'href="control-center.css"' in html
    assert 'src="control-center.js"' in html
    assert "location.protocol==='http:'" in html
    assert "/api/v1/dashboard/summary" in js
    assert "/api/v1/dashboard/incidents" in js
    assert "/api/v1/dashboard/services" in js
    assert "X-API-Key" in js


def test_dashboard_route_and_api_are_registered():
    source = Path("apps/api/main.py").read_text(encoding="utf-8")
    dashboard_api = Path("apps/api/dashboard_incidents.py").read_text(encoding="utf-8")
    assert '@app.get("/dashboard"' in source
    assert '@app.get("/dashboard/control-center.css"' in source
    assert '@app.get("/dashboard/control-center.js"' in source
    assert "dashboard_incidents.router" in source
    assert "dashboard.router" in source
    assert '@router.get("/dashboard/services")' in dashboard_api


def test_dashboard_html_css_and_js_are_actually_served_over_http():
    client = TestClient(app)

    html = client.get("/dashboard/")
    assert html.status_code == 200
    assert "text/html" in html.headers.get("content-type", "")
    assert "AIOps Control Center" in html.text
    assert "Operator Attention Queue" in html.text
    assert "Service Health" in html.text

    css = client.get("/dashboard/control-center.css")
    assert css.status_code == 200
    assert "text/css" in css.headers.get("content-type", "")
    assert ".app-shell" in css.text
    assert ".incident-layout" in css.text

    js = client.get("/dashboard/control-center.js")
    assert js.status_code == 200
    assert "javascript" in js.headers.get("content-type", "")
    assert "loadAll" in js.text
    assert "renderServices" in js.text
