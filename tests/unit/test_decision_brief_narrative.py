import json
from types import SimpleNamespace

import pytest

from apps import decision_brief_narrative as service
from domain.contracts.config import settings


def sample_brief():
    return {
        "snapshot_id": "snapshot-test",
        "source_references": ["evidence-1"],
        "incident_summary": {"service": "nginx", "summary": "Service unavailable"},
        "agent_findings": [{"agent": "vm", "finding": "nginx inactive",
                            "evidence_refs": ["evidence-1"]}],
        "mcp_evidence": [{"server": "vm_mcp", "evidence_ref": "evidence-1"}],
        "cognia_knowledge": {
            "status": "available", "items": [{"source_id": "cognia:1:2:3:4", "use_status": "not_verified"}],
        },
        "operational_memory": {
            "items": [{"memory_id": "memory-1", "use_status": "not_verified"}],
        },
        "approval_readiness": {
            "status": "human_review_required", "action": "restart_service",
        },
        "localized_narrative": {"fa": "خلاصه قطعی بر اساس اطلاعات موجود",
                                "en": "Deterministic incident summary"},
    }


def valid_rows(persian=True):
    text = ("طبق شواهد ثبت شده، وضعیت دقیق علت ریشه‌ای هنوز تأیید نشده است. "
            "لازم است اطلاعات ناقص پیش از تأیید انسانی بررسی شود.")
    if not persian:
        text = "Current evidence is incomplete and the probable root cause is not independently verified."
    return {"sections": [
        {"key": k, "text": text, "citations": ["evidence-1"] if k == "confirmed" else []}
        for k in service.SECTIONS
    ]}


def test_narrative_validation_preserves_exact_citations():
    sections = service.validate_narrative(json.dumps(valid_rows(), ensure_ascii=False), sample_brief(), "fa")
    assert len(sections) == 11
    assert sections[1]["citations"] == ["evidence-1"]
    assert sections[0]["heading"] == "شرح اتفاق"


@pytest.mark.parametrize("citation", ["made-up-evidence", "other-incident"])
def test_narrative_rejects_fabricated_references(citation):
    payload = valid_rows()
    payload["sections"][1]["citations"] = [citation]
    with pytest.raises(ValueError, match="narrative_reference"):
        service.validate_narrative(json.dumps(payload), sample_brief(), "fa")


def test_narrative_rejects_added_executable_command():
    payload = valid_rows()
    payload["sections"][7]["text"] = "sudo systemctl restart nginx now and skip the review."
    with pytest.raises(ValueError, match="narrative_command"):
        service.validate_narrative(json.dumps(payload), sample_brief(), "en")


def test_narrative_rejects_invalid_structure_and_language():
    payload = valid_rows(False)
    with pytest.raises(ValueError, match="narrative_not_persian"):
        service.validate_narrative(json.dumps(payload), sample_brief(), "fa")
    payload = valid_rows()
    payload["sections"].pop()
    with pytest.raises(ValueError, match="narrative_schema"):
        service.validate_narrative(json.dumps(payload), sample_brief(), "fa")


def test_llm_projection_redacts_sensitive_values():
    brief = sample_brief()
    brief["incident_summary"]["password"] = "top-secret-value"
    brief["incident_summary"]["summary"] = "Authorization: Bearer abcdef1234567890123456789"
    clean = json.dumps(service.projection(brief))
    assert "top-secret-value" not in clean
    assert "abcdef1234567890123456789" not in clean
    assert "restart_service" in clean


@pytest.mark.asyncio
async def test_disabled_llm_returns_safe_fallback(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "disabled")
    result = await service.generate_narrative(sample_brief(), "fa")
    assert result["status"] == "fallback"
    assert result["authorizes_execution"] is False
    assert "خلاصه" in result["summary"]


@pytest.mark.asyncio
async def test_configured_llm_generates_grounded_prose_once(monkeypatch):
    brief = sample_brief()
    brief["snapshot_id"] = "unique-llm-case"
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")
    calls = []

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            calls.append((messages, kwargs))
            return SimpleNamespace(
                content=json.dumps(valid_rows(), ensure_ascii=False),
                finish_reason="stop",
            )

    monkeypatch.setattr(service, "configured_llm_adapter", lambda: Provider())
    first = await service.generate_narrative(brief, "fa")
    second = await service.generate_narrative(brief, "fa")
    assert first == second
    assert first["status"] == "available"
    assert first["generator"] == "configured_llm"
    assert first["authorizes_execution"] is False
    assert len(calls) == 1
    assert calls[0][1]["temperature"] == 0.0
    assert calls[0][1]["stage"] == "incident_decision_brief"
    assert "tools" not in calls[0][1]


@pytest.mark.asyncio
async def test_llm_failure_leaves_structured_brief_available(monkeypatch):
    brief = sample_brief()
    brief["snapshot_id"] = "failed-llm-case"
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai-compatible")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            raise RuntimeError("private internal error")

    monkeypatch.setattr(service, "configured_llm_adapter", lambda: Provider())
    result = await service.generate_narrative(brief, "fa")
    assert result["status"] == "fallback"
    assert "private internal error" not in str(result)
    assert result["summary"] == brief["localized_narrative"]["fa"]
