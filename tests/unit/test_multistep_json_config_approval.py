"""Regression: malformed 16KB .NET JSON reaches governed approval review.

A successful worker JSON parse is only syntax evidence. Tests never write to
a VM or claim application/runtime health; validation and Approval stay gated.
"""
import base64
import hashlib
import json

import pytest

from apps.api.config_change_review import ConfigReviewResponse, _matching_proposal
from apps.config_change_auto_queue import auto_queue_candidate
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from integrations.vm.general_config_review import local_config_review
from integrations.vm.governed_config_change import rebuild_json_candidate
from integrations.vm.json_syntax_candidate import (
    bounded_json_repair_with_edits, bounded_json_syntax_fix,
    deterministic_json_punctuation_fix,
)


PATH = "/data/gfp/gfpapi/appsettings.json"


def _fixture():
    source = json.dumps({f"key{i:03d}": {"enabled": True} for i in range(300)},
                        indent=2) + "\n"
    assert len(source) > 16000
    # Two independent parser failures: an extra opening brace followed by
    # an extra closing brace. One-token logic cannot validate the whole file.
    bad = source.replace('"key036": {', '"key036": {{', 1)
    bad = bad.replace('    },\n    "key037"', '    }},\n    "key037"', 1)
    # Source never leaks in the production candidate metadata.
    assert json.loads(source)
    return bad, source


def test_worker_bounded_json_repairs_multiple_errors_and_preserves_all_values():
    source, correct = _fixture()
    assert deterministic_json_punctuation_fix(source) is None
    result = bounded_json_repair_with_edits(source)
    assert result is not None
    updated, steps = result
    assert updated == correct
    assert 1 < len(steps) <= 3
    assert bounded_json_syntax_fix(source) == updated
    assert json.loads(updated) == json.loads(correct)
    assert "enabled" not in str(steps)
    assert "key036" not in str(steps)


def test_no_rewrite_or_unsupported_multi_error_or_secret_edit():
    assert bounded_json_syntax_fix('{"password":"SECRET","ok":true}') is None
    assert bounded_json_syntax_fix('{"key": "x{y}"}') is None
    assert bounded_json_syntax_fix('{"a":1, wrong:2, also_wrong:3}') is None
    assert bounded_json_syntax_fix('{"a":') is None


def test_local_review_proposes_replayable_hash_bound_staged_repair():
    original, expected = _fixture()
    encoded = base64.b64encode(original.encode()).decode()
    preview = local_config_review(encoded, path=PATH)
    assert preview["status"] == "candidate_proposed"
    assert preview["proposed_change"] == "repair_json_bounded_syntax"
    assert preview["validation_status"] == "FORMAT_CANDIDATE_VALID_ONLY"
    assert preview["candidate_hash"] == hashlib.sha256(expected.encode()).hexdigest()
    assert preview["source_hash"] == hashlib.sha256(original.encode()).hexdigest()
    assert len(preview["redacted_changes"]) == 2
    assert preview["execution_authority"] is False
    assert preview["apply_eligible"] is False
    assert expected not in str(preview)
    rebuilt = rebuild_json_candidate(
        encoded=encoded, path=PATH, original_sha256=preview["source_hash"],
        candidate_sha256=preview["candidate_hash"],
        proposed_change="repair_json_bounded_syntax",
    )
    assert rebuilt == expected
    with pytest.raises(ValueError, match="config_source_hash_drift"):
        rebuild_json_candidate(
            encoded=base64.b64encode((original + " ").encode()).decode(), path=PATH,
            original_sha256=preview["source_hash"],
            candidate_sha256=preview["candidate_hash"],
            proposed_change="repair_json_bounded_syntax",
        )


@pytest.mark.asyncio
async def test_dynamic_proposal_enters_prevalidation_queue():
    original, _ = _fixture()
    preview = local_config_review(
        base64.b64encode(original.encode()).decode(), path=PATH,
    )
    evidence = [
        {"source": "vm_mcp", "reference": "vm:review:1",
         "raw_data": {"success": True, "diagnostic": "service_config_review",
                      "service": "gfpapi", **preview}},
        {"source": "vm_mcp", "reference": "vm:syntax:1",
         "raw_data": {"success": True, "diagnostic": "dotnet_config_syntax",
                      "service": "gfpapi", "syntax_valid": False,
                      "files": [{"file": "appsettings.json",
                                 "status": "invalid_json_syntax", "line": 74}]}}
    ]
    state = {"service_name": "gfpapi", "context": {"evidence": evidence}}
    report = await DynamicInvestigationPlanner.propose(state, adapter=None)
    assert report["config_proposal"]["status"] == "candidate_proposed"
    assert report["config_proposal"]["proposed_change"] == "repair_json_bounded_syntax"
    state["context"]["dynamic_investigation"] = report
    proposal = auto_queue_candidate(state)
    assert proposal is not None
    intent = ConfigReviewResponse(
        decision="request_isolated_validation",
        expected_original_sha256=proposal["original_sha256"],
        expected_candidate_sha256=proposal["candidate_sha256"],
    )
    assert _matching_proposal(proposal, intent)
    assert proposal["execution_authority"] is False
