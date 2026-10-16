"""Regression coverage for slow complete-file repair and minimal JSON corrections."""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import httpx
import pytest

from integrations.vm.full_config_llm_repair import (
    _candidate_preview,
    _is_exact_json_key_quote_fix,
    review_complete_config,
)
from integrations.vm.mcp_client import VMEdgeMCPClient


def test_json_key_quotes_are_the_only_allowed_value_token_exception():
    original = '{"enabled": true,\nretryCount: 3}\n'
    corrected = '{"enabled": true,\n"retryCount": 3}\n'
    assert _is_exact_json_key_quote_fix(original, corrected)
    result = _candidate_preview(original, corrected, diagnostic_line=2)
    assert result["status"] == "llm_candidate_proposed"
    assert result["validator_executed_on_proposal"] is False
    assert result["execution_authority"] is False
    assert result["apply_eligible"] is False
    assert result["changed_line_numbers"] == [2]
    assert not _is_exact_json_key_quote_fix(original, original.replace("3", "4"))
    assert _candidate_preview(original, corrected.replace("3", "4"), diagnostic_line=2)[
        "status"
    ] == "llm_candidate_rejected"


@pytest.mark.asyncio
async def test_json_error_line_recovered_without_vendor_validator(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair

    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://trusted.example")
    original = '{"enabled": true,\nretryCount: 3}\n'
    corrected = original.replace("retryCount: 3", '"retryCount": 3')

    class Model:
        async def generate(self, prompt, **kwargs):
            payload = json.loads(prompt)
            assert payload["vendor_error_line"] == 2
            assert payload["complete_config"] == original
            assert kwargs["stage"] == "full_config_llm_repair"
            return SimpleNamespace(
                content=json.dumps({"corrected_config": corrected}),
                finish_reason="stop",
            )

    result = await review_complete_config(
        base64.b64encode(original.encode()).decode(),
        service="gfpapi", path="/data/gfp/gfpapi/appsettings.json",
        model=Model(),
    )
    assert result["status"] == "llm_candidate_proposed"
    assert result["validation_status"] == "UNVERIFIED"
    assert result["validator_executed_on_proposal"] is False
    assert original not in json.dumps(result)
    assert corrected not in json.dumps(result)


@pytest.mark.asyncio
async def test_full_config_mcp_call_uses_single_long_bounded_attempt(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "MCP_TIMEOUT_SECONDS", 20)

    client = VMEdgeMCPClient(server_url="http://vm-mcp.example/mcp")
    calls = []

    class StubTransport:
        async def post(self, url, **kwargs):
            calls.append(kwargs)
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 8,
                      "result": {"content": [{"status": "llm_repair_timeout"}]}},
                request=httpx.Request("POST", url),
            )

        async def aclose(self):
            pass

    client._client = StubTransport()
    try:
        result = await client._post(
            {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
             "params": {"name": "service_config_llm_repair",
                        "arguments": {"target": "192.0.2.1", "service": "gfpapi"}}},
            tool_name="service_config_llm_repair",
        )
        assert result["result"]["content"][0]["status"] == "llm_repair_timeout"
        assert len(calls) == 1
        assert calls[0]["timeout"] == 140.0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_full_config_llm_transport_does_not_replay_on_timeout(monkeypatch):
    from integrations.llm import openai_compatible as provider_module
    monkeypatch.setattr(provider_module.settings, "RETRY_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(provider_module.settings, "LLM_TIMEOUT_SECONDS", 20)

    calls = []
    timeouts = []

    class StubGateway:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            calls.append(kwargs)
            raise httpx.ReadTimeout("test gateway timeout")

    def fake_client(*, timeout, component):
        timeouts.append(timeout)
        return StubGateway()

    monkeypatch.setattr(provider_module, "insecure_async_client", fake_client)
    provider = provider_module.OpenAICompatibleLLMProvider(
        "https://trusted.example", "assistance-model"
    )
    with pytest.raises(httpx.ReadTimeout):
        await provider.generate(
            "safe fake config", stage="full_config_llm_repair",
            completion_repair_attempts=0,
        )
    assert len(calls) == 1
    assert timeouts == [90.0]
