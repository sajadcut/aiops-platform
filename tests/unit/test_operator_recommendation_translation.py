"""Bilingual operator recommendation: actual Persian, original English intact."""
from types import SimpleNamespace
from uuid import uuid4

import pytest

from apps.operator_summary import build_operator_summary
from apps import recommendation_translation as service
from domain.contracts.config import settings


def summary_for(plan):
    return build_operator_summary(
        incident={"id": str(uuid4()), "service": "nginx", "severity": "medium"},
        durable_evidence=[], findings=[], checkpoint={"state": {"final_plan": plan}},
    )


def test_freeform_english_json_is_never_falsely_labeled_as_persian():
    plan = '{"assessment":{"summary":"TCP port 86 is confirmed down on 10.100.6.199",' \
           '"root_cause_status":"unconfirmed"},"action_plan":{"conditional_actions":[' \
           '{"condition":"If SSH is restored","action":"Start nginx with `systemctl start nginx`",' \
           '"requires_approval":true}]}}'
    action = summary_for(plan)["recommended_action"]
    assert action["text_en"] == plan
    assert action["text_fa"] is None
    assert action["needs_persian_translation"] is True
    assert plan not in summary_for(plan)["summary_fa"]


def test_governed_action_persian_label_is_real_persian_not_english_command():
    summary = build_operator_summary(
        incident={"id": str(uuid4()), "service": "nginx"},
        durable_evidence=[], findings=[],
        checkpoint={"state": {"execution_request": {
            "action": "start_service", "tool_name": "ssh_vm", "target": "10.100.6.199"
        }}},
    )
    action = summary["recommended_action"]
    assert "راه‌اندازی سرویس" in action["text_fa"]
    assert action["text_en"].startswith("Proposed action: start_service")
    assert not action.get("needs_persian_translation")


def test_native_persian_plan_keeps_language_label_correct():
    action = summary_for("قبل از هر اقدام وضعیت سرویس را بررسی کنید.")["recommended_action"]
    assert action["text_fa"].startswith("قبل از")
    assert action["text_en"] is None


@pytest.mark.asyncio
async def test_llm_translates_full_plan_display_only_using_configured_provider(monkeypatch):
    source = ('TCP port 86 on 10.100.6.199 is down. If SSH access is restored, '
              'start nginx with `systemctl start nginx` after human approval.')
    translated = (
        'ارزیابی: پورت 86 در میزبان 10.100.6.199 در دسترس نیست؛ علت ریشه‌ای '
        'از شواهد موجود تأیید نشده است.\n'
        'اقدام مشروط: فقط در صورت بازیابی دسترسی SSH و بررسی وضعیت سرویس، '
        'فرمان `systemctl start nginx` پس از دریافت تأیید انسانی قابل بررسی است.\n'
        'این ترجمه صرفاً برای نمایش است و مجوز اجرای عملیات ایجاد نمی‌کند.'
    )
    calls = []

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            calls.append((messages, kwargs))
            return SimpleNamespace(content=translated, finish_reason="stop")

    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.test")
    monkeypatch.setattr(settings, "LLM_MODEL", "assistance-model")
    monkeypatch.setattr(service, "configured_llm_adapter", lambda: Provider())
    result = await service.translate_recommendation(source)
    assert result == translated
    assert len(calls) == 1
    assert calls[0][1]["temperature"] == 0.0
    assert calls[0][1]["stage"] == "operator_recommendation_translation"
    assert "No tools" not in str(calls[0][1])  # no tool kwargs were supplied
    assert calls[0][0][0]["role"] == "system"
    assert "Do NOT diagnose" in calls[0][0][0]["content"]
    assert await service.translate_recommendation(source) == translated
    assert len(calls) == 1  # same source snapshot gets a cached display value


@pytest.mark.asyncio
async def test_translation_rejects_missing_targets_or_commands(monkeypatch):
    source = 'TCP port 86 on 10.100.6.198. Run `systemctl start nginx` after approval.'
    translated = 'وضعیت بررسی شد و امکان اجرای عملیات با مجوز وجود دارد؛ نتیجه علت باید با شواهد زنده بررسی شود.'
    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            return SimpleNamespace(content=translated, finish_reason="stop")
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai-compatible")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "http://llm.test")
    monkeypatch.setattr(settings, "LLM_MODEL", "fake")
    monkeypatch.setattr(service, "configured_llm_adapter", lambda: Provider())
    with pytest.raises(service.TranslationUnavailable, match="translation_missing_target"):
        await service.translate_recommendation(source)


@pytest.mark.asyncio
async def test_translation_fail_closed_when_model_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "mock")
    with pytest.raises(service.TranslationUnavailable, match="translation_model_not_configured"):
        await service.translate_recommendation('Review the unavailable nginx service on port 86.')


def test_authenticated_get_route_and_no_execution_authority():
    from apps.api.main import app
    paths = {getattr(route, "path", ""): route for route in app.routes}
    route = paths["/api/v1/incidents/{incident_id}/operator-recommendation/fa"]
    assert route.methods == {"GET"}
    assert "require_permission" in str(route.dependant.dependencies)
    source = open("apps/api/incident_resources.py", encoding="utf-8").read()
    assert "translate_recommendation(source)" in source
    assert '"execution_authority": False' in source
    http_logging = open("apps/api/http_logging.py", encoding="utf-8").read()
    assert 'path.endswith("/operator-recommendation/fa")' in http_logging
