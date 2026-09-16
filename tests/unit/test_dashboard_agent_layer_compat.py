from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from agents.shared.registry import _AGENT_CLASSES


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboards"


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_default_agent_configuration_and_dashboard_catalog_stay_in_sync():
    env_text = _text(".env.example")
    match = re.search(r"^AGENT_ENABLED_AGENTS=(.+)$", env_text, flags=re.MULTILINE)
    assert match, "AGENT_ENABLED_AGENTS missing from .env.example"
    enabled = set(json.loads(match.group(1)))
    known = set(_AGENT_CLASSES)

    assert enabled == known, {
        "missing_from_default_config": sorted(known - enabled),
        "unknown_in_default_config": sorted(enabled - known),
    }

    api_source = _text("apps/api/agents.py")
    dashboard_js = _text("dashboards/control-center.js")
    actions_js = _text("dashboards/approval-actions.js")
    assert '"items": [manifest.__dict__ for manifest in manifests]' in api_source
    assert "S.agents = c.items || []" in dashboard_js
    assert "S.agents.map" in dashboard_js
    assert "/api/v1/agents/catalog" in dashboard_js
    assert "/api/v1/agents/metrics" in dashboard_js

    # The catalog page consumes the complete manifest contract dynamically. New
    # registered agents therefore inherit the same evidence/handoff/telemetry UI
    # without a dashboard-side allow-list.
    for token in [
        "evidence_requirements",
        "handoff_targets",
        "production_status",
        "average_evidence_coverage",
        "metric.failures",
        "metric.handoffs",
        "metric.conflicts",
    ]:
        assert token in actions_js


def test_agent_analysis_details_reach_incident_dashboard_without_domain_whitelist():
    orchestrator = _text("apps/orchestrator/e2e_graph.py")
    lifecycle_api = _text("apps/api/incident_resources.py")
    dashboard_js = _text("dashboards/control-center.js")
    actions_js = _text("dashboards/approval-actions.js")

    # Specialist outputs are serialized as the full AgentOutput contract, which
    # includes analysis_details. The lifecycle endpoint forwards those results
    # instead of rebuilding a lossy per-domain schema.
    assert 'data = output.model_dump(mode="json")' in orchestrator
    assert 'state["analysis_results"] = findings' in orchestrator
    assert '"agents": state.get("analysis_results") or []' in lifecycle_api

    # Keep the legacy raw fallback, then enhance it with a schema-tolerant
    # structured view. No network/storage/database/etc. allow-list is required.
    assert "(l.agents || []).map" in dashboard_js
    assert "JSON.stringify(a, null, 2)" in dashboard_js
    assert "a.agent_name || a.agent || 'agent'" in dashboard_js
    assert "key.endsWith('_analysis')" in actions_js
    assert "analyzer_telemetry" in actions_js
    assert "missing_evidence" in actions_js
    assert "stale_evidence_ids" in actions_js
    assert "next_best_evidence" in actions_js
    assert "handoff_agents" in actions_js
    assert "Full structured analysis" in actions_js
    assert "dashboard preview truncated" in actions_js


def test_dashboard_static_id_references_have_a_rendered_target():
    html = _text("dashboards/index.html")
    control = _text("dashboards/control-center.js")
    actions = _text("dashboards/approval-actions.js")
    combined_templates = "\n".join([html, control, actions])

    declared_ids = set(re.findall(r'id=["\']([A-Za-z0-9_-]+)["\']', combined_templates))
    referenced_ids = set(re.findall(r"\$\(['\"]#([A-Za-z0-9_-]+)['\"]\)", control + "\n" + actions))
    referenced_ids.update(
        re.findall(r"document\.querySelector\(['\"]#([A-Za-z0-9_-]+)['\"]\)", actions)
    )

    missing = sorted(referenced_ids - declared_ids)
    assert not missing, f"Dashboard selectors without rendered targets: {missing}"


def test_dashboard_api_calls_match_registered_backend_surfaces():
    control = _text("dashboards/control-center.js")
    actions = _text("dashboards/approval-actions.js")
    main_api = _text("apps/api/main.py")
    dashboard_api = _text("apps/api/dashboard.py")
    dashboard_incidents = _text("apps/api/dashboard_incidents.py")
    incident_resources = _text("apps/api/incident_resources.py")
    agents_api = _text("apps/api/agents.py")
    e2e_api = _text("apps/api/e2e_workflow.py")
    execution_api = _text("apps/api/execution.py")

    assert "/api/v1/dashboard/summary" in control
    assert '@router.get("/dashboard/summary")' in dashboard_api
    assert "/api/v1/dashboard/incidents?limit=100" in control
    assert '@router.get("/dashboard/incidents")' in dashboard_incidents
    assert "/api/v1/dashboard/services?limit=100" in control
    assert '@router.get("/dashboard/services")' in dashboard_incidents
    assert "/api/v1/health" in control
    assert "(health.router, [\"Health\"])" in main_api
    assert "/api/v1/agents/catalog" in control
    assert '@router.get("/agents/catalog")' in agents_api
    assert "/api/v1/agents/metrics" in control
    assert '@router.get("/agents/metrics")' in agents_api
    assert "/operator-summary" in actions
    assert '@router.get("/incidents/{incident_id}/operator-summary")' in incident_resources
    assert "/workflow/e2e/" in actions
    assert '@router.post("/workflow/e2e/{incident_id}/resume")' in e2e_api
    assert "/approve" in actions and "/reject" in actions
    assert "approve_approval" in execution_api and "reject_approval" in execution_api


def test_dashboard_javascript_and_inline_scripts_parse_when_node_is_available():
    node = shutil.which("node")
    if not node:
        # Developer machines are not required to install Node just to run the
        # Python suite. GitHub-hosted runners provide Node and execute this gate.
        return

    scripts = [
        DASHBOARD / "control-center.js",
        DASHBOARD / "approval-actions.js",
    ]
    for script in scripts:
        result = subprocess.run(
            [node, "--check", str(script)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"{script.name}: {result.stderr or result.stdout}"

    html = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, flags=re.DOTALL | re.IGNORECASE)
    assert inline_scripts, "Expected dashboard bootstrap inline script"
    for index, script in enumerate(inline_scripts):
        with tempfile.NamedTemporaryFile("w", suffix=f"-{index}.js", encoding="utf-8", delete=False) as handle:
            handle.write(script)
            path = Path(handle.name)
        try:
            result = subprocess.run(
                [node, "--check", str(path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, f"inline script {index}: {result.stderr or result.stdout}"
        finally:
            path.unlink(missing_ok=True)
