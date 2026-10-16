"""Explicit full-file LLM option must honor .NET JSONC parser positions.

This is a fake LLM / fake vault test: no production write or approval.
"""
import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from integrations.vm.dotnet_local_validator import normalize_dotnet_json
from integrations.vm.full_config_llm_repair import (
    _candidate_preview, review_complete_config,
)


@pytest.mark.asyncio
async def test_full_file_llm_normalizes_jsonc_then_seals_replayable_strict_candidate(monkeypatch):
    from integrations.vm import full_config_llm_repair as module

    monkeypatch.setattr(module.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(module.settings, "LLM_BASE_URL", "https://trusted-gateway.example")
    original = (
        '{\n  // .NET comment precedes true fault\n'
        '  "security": {"token": "SECRET_DO_NOT_OUTPUT",},\n'
        '  "settings": {\n'
        '     brokenKey: true\n'
        '  }\n}\n'
    )
    attempts = []
    vaulted = []

    class FakeModel:
        async def generate(self, prompt, **kwargs):
            attempts.append(kwargs["stage"])
            payload = json.loads(prompt)
            if kwargs["stage"] == "full_config_llm_repair":
                assert payload["complete_config"] == original
                return SimpleNamespace(content="invalid response", finish_reason="stop")
            assert kwargs["stage"] == "iterative_config_grammar_repair"
            source = payload["complete_config"]
            assert "SECRET_DO_NOT_OUTPUT" in source
            assert "// .NET comment" not in source
            line = payload["error"]["line"]
            assert line == 5
            row = source.splitlines()[line - 1]
            begin = row.index("brokenKey") + 1
            end = begin + len("brokenKey")
            return SimpleNamespace(content=json.dumps({"edits": [
                {"line": line, "column": begin, "old": "", "new": '"'},
                {"line": line, "column": end, "old": "", "new": '"'},
            ]}), finish_reason="stop")

    def fake_store(**kwargs):
        vaulted.append(kwargs)
        return {"candidate_stored": True, "candidate_ttl_seconds": 3600}

    monkeypatch.setattr(module, "store_candidate", fake_store)
    output = await review_complete_config(
        base64.b64encode(original.encode()).decode(),
        service="gfpapi", path="/data/gfp/gfpapi/appsettings.json",
        target="10.248.16.82", model=FakeModel(),
    )
    assert output["status"] == "llm_candidate_proposed"
    assert output["candidate_stored"] is True
    assert output["candidate_generation_mode"] == "llm_dotnet_jsonc_bounded_edits"
    assert len(vaulted) == 1
    candidate = vaulted[0]["candidate"]
    assert json.loads(candidate)["security"]["token"] == "SECRET_DO_NOT_OUTPUT"
    assert vaulted[0]["source_hash"] == hashlib.sha256(original.encode()).hexdigest()
    assert vaulted[0]["candidate_hash"] == hashlib.sha256(candidate.encode()).hexdigest()
    # Exact same independent guard used before staged validation and Apply.
    preview = _candidate_preview(
        normalize_dotnet_json(original), candidate,
        expanded_json_grammar=True,
    )
    assert preview["status"] == "llm_candidate_proposed"
    assert preview["candidate_hash"] == vaulted[0]["candidate_hash"]
    assert output["execution_authority"] is False
    assert output["apply_eligible"] is False
    assert "SECRET_DO_NOT_OUTPUT" not in json.dumps(output)
