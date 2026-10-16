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
