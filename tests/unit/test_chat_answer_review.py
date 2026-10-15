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

@pytest.mark.asyncio
async def test_chatbot_inventory_request_never_calls_vm_tool_or_intent_router(monkeypatch):
    from uuid import UUID
    from apps.chatbot import service as chatbot_module
    from apps.chatbot.models import ChatMessageRequest
    from apps.chatbot.service import ChatbotService
    from apps.security.oidc import Identity

    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm-allowed-test"])
    messages = []
    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
    class Store:
        def __init__(self, db): pass
        async def add_message(self, sid, role, content, metadata):
            messages.append((role, content, metadata))
        async def history(self, sid, limit): return []
    async def session(self, db, identity, requested):
        return {"session_id": UUID("11111111-1111-4111-8111-111111111111")}
    async def audit(*args, **kwargs): return None
    class Reviewer:
        def __init__(self): self.calls = []
        async def generate(self, prompt, **kwargs):
            self.calls.append(kwargs.get("stage"))
            # Inventory contents must not leave the server through model prompts.
            assert "vm-allowed-test" not in prompt
            return type("Response", (), {"content": '{"verdict":"consistent"}'})()
        async def generate_with_messages(self, *args, **kwargs):
            raise AssertionError("No target-status intent or VM tool should be selected")

    monkeypatch.setattr(chatbot_module, "AsyncSessionLocal", DB)
    monkeypatch.setattr(chatbot_module, "ChatStore", Store)
    monkeypatch.setattr(ChatbotService, "_session", session)
    monkeypatch.setattr(ChatbotService, "_audit", staticmethod(audit))
    llm = Reviewer()
    chatbot = ChatbotService(llm)
    result = await chatbot.message(
        Identity(subject="reviewer", roles=("sre",)),
        ChatMessageRequest(message="لیست سرور های allowhost بده"),
    )
    assert result.kind == "answer" and "vm-allowed-test" in result.message
    assert llm.calls == ["chatbot_answer_review"]
    assert [role for role, _, _ in messages] == ["user", "assistant"]

    denied = await chatbot.message(
        Identity(subject="readonly", roles=("viewer",)),
        ChatMessageRequest(message="لیست سرور های allowhost بده"),
    )
    assert denied.kind == "answer" and "vm-allowed-test" not in denied.message
    assert "SRE" in denied.message


@pytest.mark.asyncio
async def test_incident_chat_inventory_avoids_vm_and_shared_audit_leak(monkeypatch):
    from types import SimpleNamespace
    from uuid import UUID
    import apps.api.incident_chat as incident_api
    import integrations.llm.openai_compatible as provider
    from apps.security.oidc import Identity

    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm-allowed-test"])
    events = []
    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
    class Audit:
        def __init__(self, db): pass
        async def list(self, *args): return []
        async def append(self, item): events.append(item)
    async def scope(db, incident_id):
        return SimpleNamespace(service="gfpapi", context={}), {"state": {"context": {}}}, []
    async def brief(db, incident_id): return {"incident_summary": {"service": "gfpapi"}}
    async def forbidden(*args, **kwargs):
        raise AssertionError("An SSH inventory request must not route to LLM intent/VM binding")
    class Reviewer:
        async def generate(self, prompt, **kwargs):
            assert "vm-allowed-test" not in prompt
            return type("Response", (), {"content": '{"verdict":"consistent"}'})()

    monkeypatch.setattr(incident_api, "AsyncSessionLocal", DB)
    monkeypatch.setattr(incident_api, "PostgreSQLAuditStore", Audit)
    monkeypatch.setattr(incident_api, "_scope", scope)
    monkeypatch.setattr(incident_api, "load_decision_brief_for_incident", brief)
    monkeypatch.setattr(incident_api, "llm_plan", forbidden)
    monkeypatch.setattr(incident_api, "resolve_vm_binding", forbidden)
    monkeypatch.setattr(provider, "configured_llm_adapter", lambda: Reviewer())
    result = await incident_api.incident_chat_message(
        UUID("11111111-1111-4111-8111-111111111111"),
        incident_api.IncidentChatMessage(message="لیست سرور های allowhost بده"),
        identity=Identity(subject="sre-test", roles=("sre",)),
    )
    assert result["kind"] == "answer" and "vm-allowed-test" in result["message"]
    assert len(events) == 2
    assert all("vm-allowed-test" not in str(event) for event in events)
