import httpx
import pytest

from agents.shared import base as agent_base
from agents.shared.base import AgentOutput, BaseAgent, StructuredAgentResponseError
from domain.contracts.config import settings
from integrations import mcp_client as mcp_module
from integrations.llm.base import LLMAdapter, LLMResponse
from integrations.mcp_client import MCPClient


class FakeLLM(LLMAdapter):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    @property
    def provider_name(self) -> str:
        return "fake"

    async def generate(
        self,
        prompt: str,
        system_prompt=None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs,
    ) -> LLMResponse:
        self.calls.append({"prompt": prompt, "max_tokens": max_tokens, "temperature": temperature})
        return self.responses.pop(0)

    async def generate_with_messages(
        self,
        messages,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs,
    ) -> LLMResponse:
        raise NotImplementedError


class DummyAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "dummy"

    @property
    def description(self) -> str:
        return "test agent"

    async def analyze(self, input_data):
        raise NotImplementedError


def _disable_agent_telemetry(monkeypatch):
    monkeypatch.setattr(agent_base.AgentTelemetry, "record", lambda *args, **kwargs: None)


def test_agent_models_normalize_qualitative_scores():
    output = AgentOutput(
        agent_name="application",
        finding_type="analysis",
        statement="test",
        confidence="low",
        hypotheses=[{"hypothesis": "network issue", "probability": "high"}],
    )

    assert output.confidence == 0.25
    assert output.hypotheses[0].probability == 0.75


def test_structured_shape_normalizes_percent_and_label_scores():
    payload = {
        "confidence": "65%",
        "hypotheses": [
            {
                "hypothesis": "dependency failure",
                "probability": "moderate",
                "evidence_ids": [],
            }
        ],
    }

    BaseAgent._validate_structured_shape(payload)

    assert payload["confidence"] == 0.65
    assert payload["hypotheses"][0]["probability"] == 0.5


@pytest.mark.asyncio
async def test_generate_structured_repairs_truncated_response_with_larger_budget(monkeypatch):
    _disable_agent_telemetry(monkeypatch)
    monkeypatch.setattr(settings, "AGENT_MAX_TOKENS", 1200)
    monkeypatch.setattr(settings, "AGENT_STRUCTURED_REPAIR_ATTEMPTS", 1)
    monkeypatch.setattr(settings, "AGENT_TIMEOUT_SECONDS", 5)
    monkeypatch.setattr(settings, "AGENT_LLM_TEMPERATURE", 0.2)

    llm = FakeLLM(
        [
            LLMResponse(
                content='{"confidence": 0.7, "statement": "truncated',
                model="assistance-model",
                finish_reason="length",
            ),
            LLMResponse(
                content='{"confidence":"low","hypotheses":[{"hypothesis":"network issue","probability":"high"}],"findings":[]}',
                model="assistance-model",
                finish_reason="stop",
            ),
        ]
    )
    agent = DummyAgent(llm)

    result = await agent.generate_structured("Return the incident analysis schema.")

    assert [call["max_tokens"] for call in llm.calls] == [1200, 2400]
    assert "compact valid JSON" in llm.calls[0]["prompt"]
    assert "REPAIR REQUIRED" in llm.calls[1]["prompt"]
    assert "numeric 0.0-1.0" in llm.calls[1]["prompt"]
    assert result["confidence"] == 0.25
    assert result["hypotheses"][0]["probability"] == 0.75
    assert agent._last_model_metadata["finish_reason"] == "stop"
    assert agent._last_model_metadata["max_tokens"] == 2400


@pytest.mark.asyncio
async def test_generate_structured_reports_persistent_truncation(monkeypatch):
    _disable_agent_telemetry(monkeypatch)
    monkeypatch.setattr(settings, "AGENT_MAX_TOKENS", 1000)
    monkeypatch.setattr(settings, "AGENT_STRUCTURED_REPAIR_ATTEMPTS", 1)
    monkeypatch.setattr(settings, "AGENT_TIMEOUT_SECONDS", 5)

    llm = FakeLLM(
        [
            LLMResponse(content="{", model="assistance-model", finish_reason="length"),
            LLMResponse(content="{", model="assistance-model", finish_reason="length"),
        ]
    )
    agent = DummyAgent(llm)

    with pytest.raises(StructuredAgentResponseError, match="agent_response_truncated"):
        await agent.generate_structured("Return JSON.")

    assert [call["max_tokens"] for call in llm.calls] == [1000, 2000]


class FakeMCPHTTPClient:
    async def post(self, url, *, json, headers):
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": json.get("id"),
                "result": {
                    "content": [{"type": "text", "text": "upstream tool failed"}],
                    "isError": True,
                },
            },
            request=request,
        )

    async def delete(self, url, *, headers):
        request = httpx.Request("DELETE", url)
        return httpx.Response(200, request=request)

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_generic_mcp_tool_is_error_is_failed_not_completed(monkeypatch):
    steps = []
    monkeypatch.setattr(mcp_module, "log_workflow_step", lambda **kwargs: steps.append(kwargs))
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)

    client = MCPClient("http://mcp.test/mcp", "test", allowed_tools={"read_safe"})
    await client._client.aclose()
    client._client = FakeMCPHTTPClient()
    client._initialized = True

    with pytest.raises(RuntimeError, match=r"mcp_tool_error:test:read_safe"):
        await client.call_tool("read_safe", {"incident_id": "inc-1"})

    read_safe_steps = [step for step in steps if step.get("action") == "read_safe"]
    assert any(step.get("status") == "failed" for step in read_safe_steps)
    assert not any(step.get("status") == "completed" for step in read_safe_steps)

    await client.close()
