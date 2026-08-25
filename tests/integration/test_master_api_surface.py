from apps.api.main import app


def test_master_api_surface_is_registered():
    routes = {
        (getattr(route, "path", ""), tuple(sorted(getattr(route, "methods", set()))))
        for route in app.routes
    }
    expected = {
        ("/api/v1/health", ("GET",)),
        ("/api/v1/incidents", ("POST",)),
        ("/api/v1/incidents/{incident_id}", ("GET",)),
        ("/api/v1/incidents/{incident_id}/analyze", ("POST",)),
        ("/api/v1/incidents/{incident_id}/context", ("GET",)),
        ("/api/v1/incidents/{incident_id}/evidence", ("GET",)),
        ("/api/v1/incidents/{incident_id}/knowledge", ("GET",)),
        ("/api/v1/incidents/{incident_id}/memory", ("GET",)),
        ("/api/v1/incidents/{incident_id}/plan", ("GET",)),
        ("/api/v1/incidents/{incident_id}/approve", ("POST",)),
        ("/api/v1/incidents/{incident_id}/execute", ("POST",)),
        ("/api/v1/incidents/{incident_id}/verification", ("GET",)),
        ("/api/v1/runbooks", ("GET",)),
        ("/api/v1/runbooks/{name}", ("GET",)),
        ("/api/v1/knowledge", ("GET", "POST")),
    }

    for path, methods in expected:
        matching = [entry for entry in routes if entry[0] == path and all(method in entry[1] for method in methods)]
        assert matching, f"Missing MASTER API route: {methods} {path}"
