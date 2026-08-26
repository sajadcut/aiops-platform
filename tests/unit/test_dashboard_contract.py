from pathlib import Path


def test_dashboard_contains_required_operational_capabilities():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    combined = html + "\n" + js
    required = [
        "Command Center",
        "Active incidents",
        "Pending approvals",
        "Verified remediations",
        "Automation success",
        "Mean confidence",
        "Operator Attention Queue",
        "Most Impacted Services",
        "Incident Workbench",
        "Incident Intelligence",
        "Service Health",
        "MCP Fabric",
        "Audit & Governance",
        "Governance Controls",
        "X-API-Key",
        "/api/v1/dashboard/summary",
        "/api/v1/dashboard/incidents",
        "/api/v1/dashboard/services",
        "/lifecycle",
        "/evidence",
        "/verification",
        "/api/v1/agents/catalog",
        "/api/v1/health",
    ]
    missing = [token for token in required if token not in combined]
    assert not missing, f"Dashboard contract missing: {missing}"
    assert "rag and memory" in combined.lower()
    assert "agents analyze and recommend" in combined.lower()


def test_dashboard_does_not_embed_demo_or_synthetic_operational_data():
    combined = (
        Path("dashboards/index.html").read_text(encoding="utf-8")
        + Path("dashboards/control-center.js").read_text(encoding="utf-8")
    ).lower()
    for forbidden in ["fake incident", "demo-incident", "mock incident", "array.from({length:18}"]:
        assert forbidden not in combined


def test_service_health_is_durable_not_static_topology():
    api = Path("apps/api/dashboard_incidents.py").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    assert '@router.get("/dashboard/services")' in api
    assert "critical_active" in api
    assert "failed_verifications" in api
    assert "serviceState" in js
    assert "topology" not in js.lower()  # dependency graph is not fabricated without durable dependency data
