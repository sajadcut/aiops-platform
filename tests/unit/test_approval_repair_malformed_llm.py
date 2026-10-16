"""End-to-end regression for a failed LLM answer and a bounded JSON fix.

No SSH writes, approvals or target services are exercised in these tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from integrations.vm.full_config_llm_repair import (
    _bounded_exact_character_edits, _candidate_preview, review_complete_config,
)
from integrations.vm.json_syntax_candidate import (
    deterministic_json_duplicate_brace_fix,
)


SOURCE = (
    '{\n'
    '  "password": "KEEP_THIS_SECRET",\n'
    '  "settings": {{\n'
    '    "enabled": true\n'
    '  }}\n'
    '}\n'
)
CORRECTED = (
    '{\n'
    '  "password": "KEEP_THIS_SECRET",\n'
    '  "settings": {\n'
    '    "enabled": true\n'
    '  }\n'
    '}\n'
)


def test_unique_double_braces_repaired_without_touching_secret_or_other_bytes():
    corrected = deterministic_json_duplicate_brace_fix(SOURCE)
    assert corrected == CORRECTED
    assert json.loads(corrected)["password"] == "KEEP_THIS_SECRET"
    assert corrected.replace('{', '').replace('}', '') == (
        SOURCE.replace('{', '').replace('}', '')
    )


def test_never_guess_when_two_or_more_possible_or_unrelated_repairs():
    assert deterministic_json_duplicate_brace_fix(
        '{"one": {{ "x":1 }}, "two":{{ "y":2 }}}\n'
    ) is None
    assert deterministic_json_duplicate_brace_fix(
        '{"password":"{{KEEP_THIS}}","ok":true}'
    ) is None


def test_large_repetitive_document_gets_exact_edit_distance():
    source = '{"values":[' + ",".join('"{{ repetitive text }}"' for _ in range(1200)) + (
        '], "bad":{{"key":1}}}'
    )
    repaired = deterministic_json_duplicate_brace_fix(source)
    assert repaired is not None
    assert json.loads(repaired)["bad"]["key"] == 1
    assert _bounded_exact_character_edits(source, repaired, 3) == 2


@pytest.mark.asyncio
async def test_invalid_llm_responses_fall_back_to_parser_and_publish_sealed_candidate(monkeypatch):
    from integrations.vm import full_config_llm_repair as mod

    monkeypatch.setattr(mod.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(mod.settings, "LLM_BASE_URL", "https://approved-gateway.example")
    attempts = []
    sealed = []

    class AlwaysBadModel:
        async def generate(self, prompt, **kwargs):
            assert json.loads(prompt)["complete_config"] == SOURCE
            attempts.append(kwargs["stage"])
            return SimpleNamespace(content="Sorry, I cannot parse it", finish_reason="stop")

    def store(**kwargs):
        sealed.append(kwargs)
        return {"candidate_stored": True}

    monkeypatch.setattr(mod, "store_candidate", store)
    result = await review_complete_config(
        base64.b64encode(SOURCE.encode()).decode(),
        service="gfpapi", path="/data/gfp/gfpapi/appsettings.json",
        model=AlwaysBadModel(), target="10.248.16.82",
    )
    assert len(attempts) == 2
    assert result["status"] == "llm_candidate_proposed"
    assert result["llm_received_complete_file"] is True
    assert result["llm_returned_complete_file"] is False
    assert result["candidate_origin"] == "deterministic_json_syntax"
    assert result["candidate_stored"] is True
    assert result["candidate_hash"] == hashlib.sha256(CORRECTED.encode()).hexdigest()
    assert sealed[0]["candidate"] == CORRECTED
    assert "KEEP_THIS_SECRET" not in json.dumps(result)
    assert result["execution_authority"] is False
    assert result["apply_eligible"] is False

    evidence = [{
        "source": "vm_mcp", "reference": "test-verified-ref",
        "raw_data": {"success": True, "diagnostic": "service_config_llm_repair",
                     **result}
    }]
    full = DynamicInvestigationPlanner.full_config_repair_evidence(
        evidence, service="gfpapi", failure=None,
    )
    assert full["candidate_origin"] == "deterministic_json_syntax"
    assert full["candidate_stored"] is True
    assert full["candidate_sha256"] == result["candidate_hash"]
    assert full["source_evidence_refs"] == ["test-verified-ref"]


def test_brace_pair_preview_allows_measured_closer_further_down():
    source = '{\n  "settings": {{\n' + '"safe": 1,\n' * 7 + (
        '"enabled": true\n  }}\n}\n'
    )
    candidate = deterministic_json_duplicate_brace_fix(source)
    assert candidate is not None
    assert _candidate_preview(
        source, candidate, diagnostic_line=2,
    )["status"] == "llm_candidate_proposed"



def test_automatic_review_and_preapproval_binds_same_two_brace_candidate():
    from integrations.vm.general_config_review import local_config_review
    from integrations.vm.governed_config_change import rebuild_json_candidate
    from apps.api.config_change_review import (
        ConfigReviewResponse, _matching_proposal,
    )

    path = "/data/gfp/gfpapi/appsettings.json"
    reviewed = local_config_review(
        base64.b64encode(SOURCE.encode()).decode(), path=path,
    )
    assert reviewed["status"] == "candidate_proposed"
    assert reviewed["proposed_change"] == "repair_json_punctuation"
    assert reviewed["validation_status"] == "FORMAT_CANDIDATE_VALID_ONLY"
    assert reviewed["apply_eligible"] is False
    rebuilt = rebuild_json_candidate(
        encoded=base64.b64encode(SOURCE.encode()).decode(), path=path,
        original_sha256=reviewed["source_hash"],
        candidate_sha256=reviewed["candidate_hash"],
        proposed_change=reviewed["proposed_change"],
    )
    assert rebuilt == CORRECTED
    proposal = {
        "service": "gfpapi",
        "config_file": path,
        "status": "candidate_proposed",
        "proposed_change": reviewed["proposed_change"],
        "original_sha256": reviewed["source_hash"],
        "candidate_sha256": reviewed["candidate_hash"],
        "source_evidence_refs": ["vm:evidence:measured"],
        "execution_authority": False,
        "apply_eligible": False,
    }
    req = ConfigReviewResponse(
        decision="request_isolated_validation",
        expected_original_sha256=proposal["original_sha256"],
        expected_candidate_sha256=proposal["candidate_sha256"],
    )
    assert _matching_proposal(proposal, req) is True
    assert reviewed["source_hash"] != reviewed["candidate_hash"]


def test_approval_scope_accepts_json_punctuation_only_after_jq_validation():
    # Explicitly guards against the historic fail-closed allowlist mismatch:
    # the repair could pass isolated jq, then fail pending -> human approval.
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    source = (root / "apps/approval_service/postgres.py").read_text()
    marker = 'if validation_scope == "generic_json_syntax_only_service_runtime_unverified":'
    section = source[source.index(marker):source.index(marker) + 400]
    assert '"repair_json_punctuation"' in section
    assert 'vendor_validator.startswith("jq empty")' in section
