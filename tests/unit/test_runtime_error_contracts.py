import pytest

from integrations.llm.base import LLMResponse
from integrations.zabbix.mcp_client import ZabbixMCPClient


def test_llm_response_accepts_nested_usage_details():
    response = LLMResponse(
        content="ok",
        model="assistance-model",
        usage={
            "prompt_tokens": 123,
            "completion_tokens": 7,
            "total_tokens": 130,
            "prompt_tokens_details": {"cached_tokens": 11},
        },
    )

    assert response.usage is not None
    assert response.usage["prompt_tokens_details"]["cached_tokens"] == 11


@pytest.mark.asyncio
async def test_zabbix_problem_get_is_error_raises_instead_of_empty_success():
    client = object.__new__(ZabbixMCPClient)

    async def fake_call_tool(tool_name, arguments):
        assert tool_name == "problem_get"
        assert arguments["search"] == {"name": "NeoBanking-6.199"}
        return {
            "content": [
                {
                    "type": "text",
                    "text": "Error executing tool problem_get: API call failed for problem.get.",
                }
            ],
            "isError": True,
        }

    client.call_tool = fake_call_tool

    with pytest.raises(RuntimeError, match=r"zabbix_mcp_tool_error:problem_get"):
        await client.get_alerts(service="NeoBanking-6.199")
