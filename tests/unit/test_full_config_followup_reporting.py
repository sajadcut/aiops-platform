"""Regression: full-file LLM review must reach the incident report, not approval."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from apps.incident_followup import followup_evidence, _LIVE_VM_CHECKS
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from apps.decision_brief import build_decision_brief


SERVICE = "nginx"
FILE = "/etc/nginx/nginx.conf"
OLD = "35d1cad5a3069983a6e18302c2e60b22d707847b38d3dde43bc165cba96c7042"
NEW = "5454fe22d15e1dece28bd01a293c89d429653a3ee5b11c8d32277a41ffd34ffb"


def candidate(*, service=SERVICE, target="192.0.2.10"):
    return {
        "success": True, "service": service, "target": target,
        "status": "llm_candidate_proposed", "config_file": FILE,
        "source_hash": OLD, "candidate_hash": NEW,
        "changed_line_count": 1, "changed_line_numbers": [103],
        "llm_received_complete_file": True, "llm_returned_complete_file": True,
        "validation_status": "UNVERIFIED", "apply_eligible": False,
        "execution_authority": False,
    }


def test_full_repair_is_durable_read_only_evidence():
    assert "service_config_llm_repair" in _LIVE_VM_CHECKS
    evidence = followup_evidence(
        action="service_config_llm_repair", observation=candidate(),
        service=SERVICE, binding={"service": SERVICE, "target": "192.0.2.10"},
        reference="chat-full-103",
    )
    assert evidence["source"] == "vm_mcp"
    assert evidence["raw_data"]["diagnostic"] == "service_config_llm_repair"
    assert evidence["raw_data"]["candidate_hash"] == NEW
    assert "corrected_config" not in str(evidence)
    assert followup_evidence(
        action="service_config_llm_repair", observation=candidate(service="other"),
        service=SERVICE, binding={"service": SERVICE, "target": "192.0.2.10"},
        reference="wrong-service",
    ) is None


def test_real_emerg_line_overrides_stale_warn_43():
    diagnostic = {
        "diagnostic": "config_validate", "success": True,
        "supported": True, "valid": False, "service": SERVICE,
        "config_file": FILE, "error_line": 43, "syntax_error": None,
        "detail": (
            '2026/10/15 [warn] user directive ignored in /etc/nginx/nginx.conf:43\n'
            '2026/10/15 [emerg] "listen" directive is not allowed here '
            'in /etc/nginx/nginx.conf:104\n'
            'nginx: configuration file test failed'
        ),
    }
    parsed = DynamicInvestigationPlanner.confirmed_config_failure([
        {"source": "vm_mcp", "reference": "validator", "raw_data": diagnostic},
    ])
    assert parsed["error_line"] == 104
    assert "listen" in parsed["error"]
    assert ":43" not in parsed["error"]


def test_model_candidate_is_metadata_only_and_cannot_be_cross_service_attached():
    rows = [{
        "source": "vm_mcp", "reference": "full-103",
        "created_at": "2026-10-15T17:19:46+00:00",
        "raw_data": {"diagnostic": "service_config_llm_repair", **candidate()},
    }]
    result = DynamicInvestigationPlanner.full_config_repair_evidence(
        rows, service=SERVICE, failure={"config_file": FILE},
    )
    assert result["candidate_sha256"] == NEW
    assert result["changed_line_numbers"] == [103]
    assert result["candidate_returned_not_stored"] is True
    assert result["validation_status"] == "UNVERIFIED"
    assert result["apply_eligible"] is False
    assert result["execution_authority"] is False
    assert not DynamicInvestigationPlanner.full_config_repair_evidence(
        rows, service="payment", failure=None,
    )
    assert not DynamicInvestigationPlanner.full_config_repair_evidence(
        rows, service=SERVICE, failure={"config_file": "/etc/other.conf"},
    )


@pytest.mark.asyncio
async def test_reassessment_planner_uses_full_file_result_but_not_executable_proposal():
    rows = [{
        "source": "vm_mcp", "reference": "validator",
        "raw_data": {
            "diagnostic": "config_validate", "success": True,
            "supported": True, "valid": False, "service": SERVICE,
            "config_file": FILE, "error_line": 104,
            "syntax_error": '"listen" directive is not allowed here',
        },
    }, {
        "source": "vm_mcp", "reference": "full-103",
        "raw_data": {"diagnostic": "service_config_llm_repair", **candidate()},
    }]
    class Model:
        async def generate_with_messages(self, *args, **kwargs):
            return SimpleNamespace(content='{"checks":[],"question":""}', finish_reason="stop")
    state = {
        "service_name": SERVICE, "knowledge_results": [],
        "coordination": {"missing_evidence": []},
        "context": {"evidence": rows},
    }
    review = await DynamicInvestigationPlanner.propose(state, adapter=Model())
    assert review["full_config_llm_repair"]["candidate_sha256"] == NEW
    assert review["full_config_llm_repair"]["changed_line_numbers"] == [103]
    assert review["config_proposal"]["candidate_sha256"] != NEW
    assert review["execution_authority"] is False


def test_decision_brief_displays_model_hash_without_enabling_apply():
    state = {
        "service_name": SERVICE,
        "context": {"dynamic_investigation": {
            "status": "advisory", "config_proposal": {
                "status": "observed", "config_file": FILE, "error_line": 43,
                "validation_status": "UNVERIFIED",
            },
            "full_config_llm_repair": {
                "status": "llm_candidate_proposed",
                "config_file": FILE, "service": SERVICE,
                "source_sha256": OLD, "candidate_sha256": NEW,
                "changed_line_count": 1, "changed_line_numbers": [103],
                "llm_received_complete_file": True,
                "llm_returned_complete_file": True,
                "candidate_returned_not_stored": True,
                "source_evidence_refs": ["full-103"],
            },
        }},
    }
    brief = build_decision_brief(
        incident={"id": "incident-full-103", "service": SERVICE,
                  "status": "analyzing"},
        operator_summary={}, checkpoint={"state": state},
        durable_evidence=[], findings=[], audit_events=[],
        now=datetime(2026, 10, 15, 17, 25, tzinfo=timezone.utc),
    )
    full = brief["dynamic_investigation"]["full_config_llm_repair"]
    assert full["candidate_sha256"] == NEW
    assert full["changed_line_numbers"] == [103]
    assert full["validation_status"] == "UNVERIFIED"
    assert full["apply_eligible"] is False
    assert full["execution_authority"] is False
    assert brief["dynamic_investigation"]["config_proposal"]["candidate_sha256"] != NEW


def test_ui_explains_two_disjoint_candidates_and_deprecates_indent_hypothesis():
    from pathlib import Path
    script = (Path(__file__).resolve().parents[2] /
              "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert "full_config_llm_repair" in script
    assert "candidate_returned_not_stored" in (
        Path(__file__).resolve().parents[2] /
        "apps/decision_brief.py").read_text(encoding="utf-8")
    assert "complete-file repair" in script
    assert "تورفتگی ناهماهنگ" in script
    assert "fullRepairHtml" in script
    assert "تست مستقلی" in script
