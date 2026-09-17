import pytest

from apps.chatbot.service import ChatbotService
from apps.chatbot.tools import CHAT_TOOL_SCHEMAS, ToolIntent
from apps.security.oidc import Identity
from integrations.llm.base import LLMAdapter, LLMResponse


class RecordingSummaryLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""
        self.system_prompt = ""

    @property
    def provider_name(self) -> str:
        return "recording-summary"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        self.system_prompt = system_prompt or ""
        return LLMResponse(content="فضای /app از داده معتبر ابزار گزارش شد.", model="recording-summary")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content="", model="recording-summary")


def _tool(name: str) -> dict:
    return next(item for item in CHAT_TOOL_SCHEMAS if item["function"]["name"] == name)


def test_system_prompt_reuses_unambiguous_context_and_never_confirms_reads():
    rows = [
        {"role": "user", "content": "cpu 10.100.6.199 چقدره"},
        {"role": "assistant", "content": "CPU گزارش شد."},
        {"role": "user", "content": "nginx بالاست؟"},
    ]
    messages = ChatbotService._history_messages(rows)
    system = messages[0]["content"]

    assert "reuse that most recent explicit value" in system
    assert "Never ask the user for a yes/no confirmation before a read-only tool call" in system
    assert "speaking Persian" in system
    assert "answer in Persian" in system
    assert "do not switch to Arabic" in system
    assert "10.100.6.199" in messages[1]["content"]
    assert messages[-1]["content"] == "nginx بالاست؟"


def test_recent_operator_context_keeps_substantive_persian_turns_for_short_followups():
    rows = [
        {"role": "user", "content": "cpu 10.100.6.199 چقدره"},
        {"role": "assistant", "content": "result"},
        {"role": "user", "content": "nginx بالاست؟"},
        {"role": "assistant", "content": "برای بررسی وضعیت سرویس"},
        {"role": "user", "content": "بله"},
    ]

    context = ChatbotService._recent_operator_context(rows)
    assert "10.100.6.199" in context
    assert "nginx بالاست؟" in context
    assert context.endswith("بله")


def test_vm_disk_tool_contract_exposes_exact_mount_available_bytes_without_confirmation():
    description = _tool("vm_diagnostics")["function"]["description"]
    assert "available bytes" in description
    assert "/app" in description
    assert "read-only" in description
    assert "never requires user confirmation" in description


@pytest.mark.asyncio
async def test_summary_receives_persian_context_and_exact_mount_payload():
    llm = RecordingSummaryLLM()
    service = ChatbotService(llm)
    intent = ToolIntent(
        semantic_name="vm_diagnostics",
        tool_name="vm_telemetry",
        action="disk_status",
        target="10.100.6.199",
        parameters={},
        mutating=False,
        risk_level="low",
    )
    payload = {
        "source": "vm_mcp",
        "result": {
            "success": True,
            "target": "10.100.6.199",
            "filesystems": [
                {
                    "filesystem": "/dev/mapper/data-app",
                    "blocks": "107374182400",
                    "used": "32212254720",
                    "available": "75161927680",
                    "use_percent": "30%",
                    "mount": "/app",
                }
            ],
        },
    }

    response = await service._summarize(
        "بله",
        intent,
        payload,
        Identity(subject="operator", roles=("sre",)),
        "session-1",
        "دیسک سرور 10.100.6.199 رو بررسی کن ببین /app چقدر خالی داره\nبله",
    )

    assert response.startswith("فضای /app")
    assert "دیسک سرور 10.100.6.199" in llm.prompt
    assert '"available": "75161927680"' in llm.prompt
    assert '"mount": "/app"' in llm.prompt
    assert "never switch to Arabic" in llm.system_prompt
    assert "do not claim that exact" in llm.system_prompt
    assert "mount information is unavailable" in llm.system_prompt
