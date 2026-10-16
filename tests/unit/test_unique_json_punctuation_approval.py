"""Regression: a measured appsettings error must not be abandoned at Approval."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from integrations.vm.json_syntax_candidate import deterministic_json_punctuation_fix
from integrations.vm.general_config_review import local_config_review
from integrations.vm.governed_config_change import rebuild_json_candidate
from apps.api.config_change_review import _matching_proposal, ConfigReviewResponse


def _encoded(source: str) -> str:
    return base64.b64encode(source.encode("utf-8")).decode("ascii")


def test_extra_delimiter_at_real_dotnet_json_error_becomes_hash_bound_candidate():
    source = '{"config": {{"enabled": true, "retries": 1}}\n'
    expected = '{"config": {"enabled": true, "retries": 1}}\n'
    assert deterministic_json_punctuation_fix(source) == expected
    path = "/data/gfp/gfpapi/appsettings.json"
    preview = local_config_review(_encoded(source), path=path)
    assert preview["status"] == "candidate_proposed"
    assert preview["proposed_change"] == "repair_json_punctuation"
    assert preview["validation_status"] == "FORMAT_CANDIDATE_VALID_ONLY"
    assert preview["apply_eligible"] is False
    assert preview["candidate_hash"] == hashlib.sha256(expected.encode()).hexdigest()
    rebuilt = rebuild_json_candidate(
        encoded=_encoded(source), path=path,
        original_sha256=preview["source_hash"],
        candidate_sha256=preview["candidate_hash"],
        proposed_change=preview["proposed_change"],
    )
    assert rebuilt == expected
    assert json.loads(rebuilt) == {"config": {"enabled": True, "retries": 1}}

    proposal = {
        "status": "candidate_proposed", "service": "gfpapi",
        "config_file": path, "source_evidence_refs": ["vm:verified:1"],
        "proposed_change": preview["proposed_change"],
        "original_sha256": preview["source_hash"],
        "candidate_sha256": preview["candidate_hash"],
        "execution_authority": False, "apply_eligible": False,
    }
    payload = ConfigReviewResponse(
        decision="request_change_approval",
        expected_original_sha256=preview["source_hash"],
        expected_candidate_sha256=preview["candidate_hash"],
    )
    assert _matching_proposal(proposal, payload) is True


def test_missing_separator_reconstructs_without_modifying_key_or_values():
    source = '{"apiKey":"SECRET_UNCHANGED", "enabled":true "retries":4}'
    patched = deterministic_json_punctuation_fix(source)
    assert patched is not None
    assert json.loads(patched) == {
        "apiKey": "SECRET_UNCHANGED", "enabled": True, "retries": 4,
    }
    assert patched.replace(",", "") == source.replace(",", "")


@pytest.mark.parametrize("source", [
    '{"a": true "b": false "c": true}',  # two errors, needs two tokens
    '{"a": 123, broken: "x"}',  # key requires different dedicated fix
    '{"valid": true}',  # already valid; no change
])
def test_no_unverified_or_multi_edit_json_candidate(source):
    assert deterministic_json_punctuation_fix(source) is None


def test_rebuild_cannot_upgrade_any_changed_or_stale_file():
    source = '{"outer": {{"value": 1}}'
    fixed = deterministic_json_punctuation_fix(source)
    assert fixed
    args = {
        "encoded": _encoded(source),
        "path": "/data/gfp/gfpapi/appsettings.json",
        "original_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "candidate_sha256": hashlib.sha256(fixed.encode()).hexdigest(),
        "proposed_change": "repair_json_punctuation",
    }
    with pytest.raises(ValueError, match="config_candidate_hash_mismatch"):
        rebuild_json_candidate(**{**args, "candidate_sha256": "a" * 64})
    with pytest.raises(ValueError, match="config_source_hash_drift"):
        rebuild_json_candidate(**{**args, "encoded": _encoded(source + " ")})



@pytest.mark.asyncio
async def test_incident_planner_exposes_unique_json_repair_to_auto_queue():
    from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
    from apps.config_change_auto_queue import auto_queue_candidate

    broken = '{"config": {{"enabled": true}}'
    path = "/data/gfp/gfpapi/appsettings.json"
    review = local_config_review(_encoded(broken), path=path)
    evidence = [{
        "source": "vm_mcp", "reference": "vm:config:verified:1",
        "raw_data": {
            "success": True, "diagnostic": "service_config_review",
            "service": "gfpapi", **review,
        },
    }, {
        "source": "vm_mcp", "reference": "vm:dotnet:verified:2",
        "raw_data": {
            "success": True, "diagnostic": "dotnet_config_syntax",
            "service": "gfpapi", "syntax_valid": False,
            "files": [{"file": "appsettings.json",
                       "status": "invalid_json_syntax", "line": 1}],
        },
    }]
    state = {"service_name": "gfpapi", "context": {"evidence": evidence}}
    outcome = await DynamicInvestigationPlanner.propose(state, adapter=None)
    assert outcome["config_proposal"]["status"] == "candidate_proposed"
    assert outcome["config_proposal"]["proposed_change"] == "repair_json_punctuation"
    assert outcome["config_proposal"]["execution_authority"] is False
    assert outcome["config_repair_attention"]["status"] == "ready_for_prevalidation"
    state["context"]["dynamic_investigation"] = outcome
    assert auto_queue_candidate(state) is not None
