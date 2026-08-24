from apps.api.main import app


def test_master_api_surface_is_registered():
    routes = {getattr(route, "path", "") for route in app.routes}
    expected = {
        "/api/v1/health",
        "/api/v1/incidents/analyze",
        "/api/v1/dashboard/summary",
        "/api/v1/approvals",
        "/api/v1/runbooks/{runbook_id}/execute",
        "/api/v1/runbooks/{runbook_id}/dry-run",
    }
    assert expected.issubset(routes)
