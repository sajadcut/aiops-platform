"""Review coherence without allowing an LLM to bypass host policies or invent facts."""
import pytest

from apps.chat_answer_review import (
    requests_vm_allowed_hosts, allowed_hosts_answer, review_answer_coherence,
    mismatched_answer_message,
)
from apps.chatbot.reliable_service import _requires_live_operational_tool
from apps.incident_copilot import fallback_intent
from domain.contracts.config import settings


@pytest.mark.parametrize("question", [
    "لیست سرور های allowhost بده",
    "لیست هاست‌های مجاز SSH رو نشون بده",
    "فهرست SSH_ALLOWED_TARGETS",
    "show allowed hosts",
    "list allowlist hosts",
    "کدام سرورهای مجاز را داریم؟",
])
def test_list_of_policy_targets_is_not_a_vm_diagnostic(question):
    assert requests_vm_allowed_hosts(question)
    assert fallback_intent(question) == "answer"
    assert not _requires_live_operational_tool(
        [{"role": "user", "content": question}], tools_available=True
    )


@pytest.mark.parametrize("question", [
    "وضعیت nginx روی 10.100.6.200 چیه؟",
    "cpu سرور 10.100.6.199 چقدره",
    "سرویس nginx را restart کن",
    "is 10.100.6.123 allowed?",
    "allowlist چیست؟",
    "لیست پادهای namespace production",
])
def test_inventory_matcher_does_not_misroute_real_operations(question):
    assert not requests_vm_allowed_hosts(question)


def test_inventory_is_from_actual_settings_only_for_privileged_operator(monkeypatch):
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", [
        "10.100.6.199", "app-vm.internal", "10.100.6.199"
    ])
    viewer = allowed_hosts_answer(("viewer",))
    operator = allowed_hosts_answer(("operator",))
    assert "SRE" in viewer and "SRE" in operator
    assert "10.100.6.199" not in viewer and "app-vm.internal" not in operator
    permitted = allowed_hosts_answer(("sre",))
    assert "2 مورد" in permitted
    assert permitted.count("10.100.6.199") == 1
    assert "app-vm.internal" in permitted
    assert "SSH_ALLOWED_TARGETS" in permitted


class ReviewLLM:
    def __init__(self, result=None, raises=False):
        self.result = result
        self.raises = raises
        self.payloads = []

    async def generate(self, prompt, **kwargs):
        self.payloads.append((prompt, kwargs))
        if self.raises:
            raise ConnectionError("reviewer offline")
        return type("Response", (), {"content": self.result})()


@pytest.mark.asyncio
async def test_review_reports_mismatch_without_authorizing_model_rewrites():
    llm = ReviewLLM('{"verdict":"mismatch","reason":"answered status instead of inventory",'
                    '"corrected_answer":"fabricated hosts"}')
    verdict, reason = await review_answer_coherence(
        llm, question="لیست سرور های allowhost بده",
        answer="این سرور در allowlist نیست",
    )
    assert verdict == "mismatch" and "status" in reason
    assert llm.payloads[0][1]["stage"] == "chat_answer_coherence"
    assert "fabricated hosts" not in mismatched_answer_message(
        "لیست سرور های allowhost بده", persian=True
    )


@pytest.mark.asyncio
async def test_reviewer_outage_does_not_create_an_authoritative_new_claim():
    llm = ReviewLLM(raises=True)
    assert (await review_answer_coherence(
        llm, question="سلامت سرویس چیست؟", answer="وضعیت با شواهد تأیید نشده است."
    ))[0] == "uncertain"


def test_both_chat_paths_reuse_shared_semantic_review_and_inventory_routing():
    from pathlib import Path
    chatbot = Path("apps/chatbot/service.py").read_text(encoding="utf-8")
    incident = Path("apps/api/incident_chat.py").read_text(encoding="utf-8")
    for source in (chatbot, incident):
        assert "requests_vm_allowed_hosts(" in source
        assert "allowed_hosts_answer(" in source
        assert "review_answer_coherence(" in source
        assert "mismatched_answer_message(" in source
    assert "policy_inventory" in incident
    assert "role_scoped_configuration" in incident
    assert "CHAT_TOOL_SCHEMAS" in chatbot
    assert "JSON.stringify({confirm: value})" in Path("dashboards/chatbot.js").read_text(encoding="utf-8")
