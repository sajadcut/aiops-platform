"""Repair model receives full original values only after explicit opt-in.

It may return a narrow line/column punctuation plan instead of rewriting the
whole secret-bearing file. Workers seal validated candidates; APIs receive no
source or secret values. No production write or auto approval.
"""
from __future__ import annotations

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from integrations.vm.full_config_llm_repair import (
    _parse_bounded_edit_plan, review_complete_config,
)


def test_grammar_edits_allow_missing_comma_but_never_change_values():
    original = '{"password":"DO_NOT_SHARE", "a":1 "b":2}\n'
    pos = original.index('"b"')
    patch = {"edits": [{"line": 1, "column": pos + 1, "old": "", "new": ","}]}
    fixed = _parse_bounded_edit_plan(original, json.dumps(patch), 1)
    assert fixed == '{"password":"DO_NOT_SHARE", "a":1 ,"b":2}\n'
    assert json.loads(fixed)["password"] == "DO_NOT_SHARE"


def test_bare_property_key_can_be_quoted_using_two_literal_edits():
    source = '{"a": 1, bare_key: 3}\n'
    begin = source.index("bare_key")
    end = begin + len("bare_key")
    plan = {"edits": [
        {"line": 1, "column": begin + 1, "old": "", "new": '"'},
        {"line": 1, "column": end + 1, "old": "", "new": '"'},
    ]}
    repaired = _parse_bounded_edit_plan(source, json.dumps(plan), 1)
    assert repaired == '{"a": 1, "bare_key": 3}\n'


@pytest.mark.parametrize("plan", [
    {"edits": [{"line": 1, "column": 2, "old": "a", "new": "b"}]},
    {"edits": [{"line": 2, "column": 1, "old": "", "new": ","}]},
    {"edits": [{"line": 1, "column": 1, "old": "", "new": "rm -rf"}]},
    {"edits": [{"line": 1, "column": 1, "old": "", "new": ","}] * 4},
])
def test_edit_plan_rejects_non_grammar_out_of_bounds_or_mass_edits(plan):
    assert _parse_bounded_edit_plan('{"a": 1}\n', json.dumps(plan), 1) is None


@pytest.mark.asyncio
async def test_full_40kb_file_and_all_values_reach_model_unchanged_but_not_incident_record(monkeypatch):
    from integrations.vm import full_config_llm_repair as mod

    monkeypatch.setattr(mod.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(mod.settings, "LLM_BASE_URL", "https://approved-gateway.example")
    source = '{"credentials": "FULL_VALUE_NOT_FOR_INCIDENT", "long":"' + ("x" * 40000) + '", "a":1 "b":2}\n'
    assert len(source.encode()) > 24 * 1024
    index = source.index('"b":2')
    stored = []
    seen = []

    class FakeModel:
        async def generate(self, prompt, **kwargs):
            payload = json.loads(prompt)
            assert payload["complete_config"] == source
            assert payload["vendor_error_line"] == 1
            seen.append(kwargs)
            return SimpleNamespace(
                content=json.dumps({"edits": [{
                    "line": 1, "column": index + 1, "old": "", "new": ","
                }]}),
                finish_reason="stop",
            )

    def seal(**kwargs):
        stored.append(kwargs)
        return {"candidate_stored": True, "candidate_ttl_seconds": 86400}

    monkeypatch.setattr(mod, "store_candidate", seal)
    result = await review_complete_config(
        base64.b64encode(source.encode()).decode(),
        service="gfpapi", path="/data/gfp/gfpapi/appsettings.json",
        model=FakeModel(), target="10.248.16.82",
    )
    assert len(seen) == 1
    assert result["complete_file_in_prompt"] is True
    assert result["source_size_bytes"] == len(source.encode())
    assert result["llm_received_complete_file"] is True
    assert result["candidate_generation_mode"] == "llm_bounded_edit_plan"
    assert result["status"] == "llm_candidate_proposed"
    assert result["candidate_stored"] is True
    assert len(stored) == 1
    assert json.loads(stored[0]["candidate"])["credentials"] == "FULL_VALUE_NOT_FOR_INCIDENT"
    assert stored[0]["candidate_hash"] == hashlib.sha256(stored[0]["candidate"].encode()).hexdigest()
    assert result["execution_authority"] is False
    assert result["apply_eligible"] is False
    assert "FULL_VALUE_NOT_FOR_INCIDENT" not in json.dumps(result)
    assert "x" * 100 not in json.dumps(result)


@pytest.mark.asyncio
async def test_no_opt_in_never_sends_complete_file(monkeypatch):
    from integrations.vm import full_config_llm_repair as mod
    monkeypatch.setattr(mod.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", False)

    class ForbiddenModel:
        async def generate(self, *args, **kwargs):
            raise AssertionError("complete config must not leave worker")

    result = await review_complete_config(
        base64.b64encode(b'{"x": invalid}').decode(),
        service="gfpapi", path="/data/gfp/gfpapi/appsettings.json",
        model=ForbiddenModel(), target="10.248.16.82",
    )
    assert result["status"] == "full_config_llm_not_enabled"
    assert result["complete_file_in_prompt"] is False
