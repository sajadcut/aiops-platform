from pathlib import Path


def test_dashboard_contains_required_operational_capabilities():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    required = [
        "Active Incidents",
        "Critical Incidents",
        "Pending Approvals",
        "Successful Remediations",
        "Failed Verifications",
        "Mean Confidence",
        "serviceFilter",
        "RCA / Final Plan",
        "Independent Verification",
        "Dry-run only",
        "Resume approved workflow",
        "X-API-Key",
        "/dashboard/summary",
        "/dashboard/incidents",
        "/lifecycle",
    ]
    missing = [token for token in required if token not in html]
    assert not missing, f"Dashboard contract missing: {missing}"
    assert "operational memory" in html.lower()


def test_dashboard_does_not_embed_demo_incident_data():
    html = Path("dashboards/index.html").read_text(encoding="utf-8").lower()
    assert "fake incident" not in html
    assert "demo-incident" not in html
    assert "mock incident" not in html
