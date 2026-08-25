from apps.api.main import app


def test_master_api_surface_is_registered():
    methods_by_path: dict[str, set[str]] = {}
    for route in app.routes:
        path = getattr(route, "path", "")
        methods_by_path.setdefault(path, set()).update(getattr(route, "methods", set()))

    expected = {
        "/api/v1/health": {"GET"},
        "/api/v1/incidents": {"POST"},
        "/api/v1/incidents/{incident_id}": {"GET"},
        "/api/v1/incidents/{incident_id}/analyze": {"POST"},
        "/api/v1/incidents/{incident_id}/context": {"GET"},
        "/api/v1/incidents/{incident_id}/evidence": {"GET"},
        "/api/v1/incidents/{incident_id}/knowledge": {"GET"},
        "/api/v1/incidents/{incident_id}/memory": {"GET"},
        "/api/v1/incidents/{incident_id}/plan": {"GET"},
        "/api/v1/incidents/{incident_id}/approve": {"POST"},
        "/api/v1/incidents/{incident_id}/execute": {"POST"},
        "/api/v1/incidents/{incident_id}/verification": {"GET"},
        "/api/v1/runbooks": {"GET", "POST"},
        "/api/v1/runbooks/{name}": {"GET"},
        "/api/v1/knowledge": {"GET", "POST"},
    }

    for path, required_methods in expected.items():
        actual = methods_by_path.get(path, set())
        missing = required_methods - actual
        assert not missing, f"Missing MASTER API methods for {path}: {sorted(missing)}"