from pathlib import Path


def test_dashboard_contains_required_operational_capabilities():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    combined = html + "\n" + js
    required = [
        "Active Incidents",
        "Critical Alerts",
        "Pending Approvals",
        "Verified Remediations",
        "Automation Success",
        "Agent Confidence",
        "Incident Intelligence",
        "MCP Servers",
        "Audit & Governance",
        "Evidence",
        "Verification",
        "X-API-Key",
        "/api/v1/dashboard/summary",
        "/api/v1/dashboard/incidents",
        "/lifecycle",
        "/evidence",
        "/verification",
        "/api/v1/agents/catalog",
        "/api/v1/health",
    ]
    missing = [token for token in required if token not in combined]
    assert not missing, f"Dashboard contract missing: {missing}"
    assert "rag/memory auxiliary" in combined.lower() or "rag and memory" in combined.lower()


def test_dashboard_does_not_embed_demo_incident_data():
    combined = (
        Path("dashboards/index.html").read_text(encoding="utf-8")
        + Path("dashboards/control-center.js").read_text(encoding="utf-8")
    ).lower()
    assert "fake incident" not in combined
    assert "demo-incident" not in combined
    assert "mock incident" not in combined
