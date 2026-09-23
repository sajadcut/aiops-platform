from pathlib import Path


def test_dashboard_contains_required_operational_capabilities():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    actions = Path("dashboards/approval-actions.js").read_text(encoding="utf-8")
    combined = html + "\n" + js + "\n" + actions
    required = [
        "Command Center",
        "Active incidents",
        "Pending approvals",
        "Approved / waiting",
        "Executions succeeded",
        "Verified remediations",
        "Partial / inconclusive",
        "Memory learned",
        "Historical Operational Memory ≠ Live Evidence",
        "Automation success",
        "Mean confidence",
        "Remediation Lifecycle",
        "Operator Attention Queue",
        "Most Impacted Services",
        "Incident Workbench",
        "Incident Intelligence",
        "Service Health",
        "MCP Fabric",
        "VM Edge MCP",
        "Cognia Knowledge",
        "Audit & Governance",
        "Governance Controls",
        "Signed Capability",
        "X-API-Key",
        "/api/v1/dashboard/summary",
        "/api/v1/dashboard/incidents",
        "/api/v1/dashboard/services",
        "/lifecycle",
        "/evidence",
        "/verification",
        "/memory?limit=5",
        "/api/v1/agents/catalog",
        "/api/v1/health",
        "/workflow/e2e/",
        "binding_complete",
        "Resume & Execute",
    ]
    missing = [token for token in required if token not in combined]
    assert not missing, f"Dashboard contract missing: {missing}"
    assert "cognia" in combined.lower()
    assert "operational memory" in combined.lower()
    assert "agents analyze and recommend" in combined.lower()
    assert "approval is bound and one-time" in combined.lower()


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
    assert "failed_executions" in api
    assert "failed_verifications" in api
    assert "partial_verifications" in api
    assert "memory_persisted" in api
    assert "serviceState" in js
    assert "topology" not in js.lower()  # dependency graph is not fabricated without durable dependency data


def test_dashboard_summary_tracks_full_governed_lifecycle():
    api = Path("apps/api/dashboard.py").read_text(encoding="utf-8")
    for token in [
        "approvals_consumed",
        "execution_success",
        "execution_failed",
        "execution_blocked",
        "verification_success",
        "verification_failed",
        "verification_partial",
        "verification_inconclusive",
        "memory_persisted",
        "memory_not_persisted",
        "verification_conclusive_rate",
        "execution_success_rate",
    ]:
        assert token in api
