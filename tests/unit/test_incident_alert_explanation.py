"""Grounded, concise Persian LLM summary is independent of the 11-part RCA."""
import json
from types import SimpleNamespace

import pytest

from apps import incident_alert_explanation as focused
from apps import decision_brief_narrative as narrative
from domain.contracts.config import settings


def _brief():
    return {
        "snapshot_id": "focus-case-redissafely-0001",
        "source_references": ["ev-redis", "ev-trigger"],
        "incident_summary": {
            "service": "GFP_Backend",
            "summary": "GFP_Backend Redis errors reached at least 10 events in the last 2 minutes",
        },
        "alert_focused_report": {
            "alert_message": "GFP_Backend Redis errors reached at least 10 events in the last 2 minutes",
            "alert_source": "Zabbix", "family": "redis",
            "next_check_fa": "لاگ خطاهای کلاینت Redis و زمان پاسخ درخواست‌ها بررسی شود.",
            "related_checks": [{
                "tool": "dependency_investigation", "status": "success",
                "scope": "service_identity_not_recorded",
                "result": "redis 10.248.34.221:6379 — TCP برقرار؛ پروتکل: client_not_installed",
                "evidence_ref": "ev-redis", "evidence_refs": ["ev-redis"],
                "endpoints": [{
                    "kind": "redis", "host": "10.248.34.221", "port": 6379,
                    "port_inferred": False,
                    "tcp_reachable": True, "protocol_status": "client_not_installed",
                    "protocol_health_verified": False,
                    "config_file": "/data/gfp/gfpapi/appsettings.json",
                    "config_key": "Redis.Endpoints.Host",
                }],
            }],
            "agent_interpretations": [],
            "root_cause_confirmed": False,
        },
        "localized_narrative": {"fa": "خلاصه عمومی رخداد", "en": "Incident report"},
    }


@pytest.mark.asyncio
async def test_focused_model_gets_real_endpoint_and_writes_persian(monkeypatch):
    received = []
    prose = (
        "هشدار از افزایش خطاهای مرتبط با Redis در برنامه خبر می‌دهد؛ "
        "با آنکه TCP موفق بوده، اتصال خود کلاینت برنامه بررسی نشده است. "
        "برای تفکیک علت باید لاگ خطاهای کلاینت و Timeout همان بازه زمانی بررسی شود."
    )

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            received.append((messages, kwargs))
            return SimpleNamespace(content=prose, finish_reason="stop")

    monkeypatch.setattr(focused, "configured_llm_adapter", lambda: Provider())
    result = await focused.explain_alert(_brief(), "fa")
    assert result["status"] == "available"
    assert result["generator"] == "configured_llm"
    assert "10.248.34.221:6379" in result["text"]
    assert "اتصال TCP موفق" in result["text"]
    assert "تست پروتکل اجرا نشده" in result["text"]
    assert prose in result["text"]
    assert result["evidence_refs"] == ["ev-redis"]
    assert result["authorizes_execution"] is False
    assert received[0][1]["stage"] == "incident_alert_explanation"
    assert received[0][1]["temperature"] == 0.0
    assert "10.248.34.221" in received[0][0][1]["content"]
    assert "client_not_installed" in received[0][0][1]["content"]


@pytest.mark.asyncio
async def test_focused_model_cannot_invent_endpoint(monkeypatch):
    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            return SimpleNamespace(
                content="در بررسی آلارم، ارتباط TCP با ردیس 8.8.8.8:6379 برقرار بوده اما سلامت برنامه معلوم نیست.",
                finish_reason="stop",
            )

    monkeypatch.setattr(focused, "configured_llm_adapter", lambda: Provider())
    result = await focused.explain_alert(_brief())
    assert result["status"] == "fallback"
    assert "8.8.8.8" not in result["text"]
    assert "10.248.34.221:6379" in result["text"]


@pytest.mark.asyncio
async def test_model_failure_keeps_specific_readable_fallback(monkeypatch):
    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            raise RuntimeError("secret provider failure")
    monkeypatch.setattr(focused, "configured_llm_adapter", lambda: Provider())
    result = await focused.explain_alert(_brief())
    assert result["status"] == "fallback"
    assert "10.248.34.221:6379" in result["text"]
    assert "client_not_installed" not in result["text"]
    assert "secret provider failure" not in str(result)
    assert result["read_only"] is True


@pytest.mark.asyncio
async def test_focused_llm_survives_main_narrative_reference_or_schema_failure(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")
    calls = []

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            calls.append(kwargs["stage"])
            if kwargs["stage"] == "incident_alert_explanation":
                return SimpleNamespace(content=(
                    "هشدار Redis درباره خطاهای برنامه است؛ تست TCP موفق "
                    "بوده ولی آزمون پروتکل انجام نشده است. بررسی لاگ "
                    "برنامه و تنظیمات کلاینت برای تشخیص علت لازم است."
                ), finish_reason="stop")
            return SimpleNamespace(content=json.dumps({"sections": []}), finish_reason="stop")

    monkeypatch.setattr(narrative, "configured_llm_adapter", lambda: Provider())
    monkeypatch.setattr(focused, "configured_llm_adapter", lambda: Provider())
    result = await narrative.generate_narrative(_brief(), "fa")
    assert result["status"] == "fallback"
    assert result["alert_explanation"]["status"] == "available"
    assert "10.248.34.221:6379" in result["alert_explanation"]["text"]
    assert calls.count("incident_alert_explanation") == 1
    assert calls.count("incident_decision_brief") == 2
    assert result["authorizes_execution"] is False


def test_exact_tcp_success_never_becomes_verified_app_health():
    brief = _brief()
    output = focused.fallback_explanation(brief)
    assert "اتصال TCP موفق" in output["text"]
    assert "سلامت کامل" in output["text"]
    assert output["evidence_refs"] == ["ev-redis"]
    assert output["authorizes_execution"] is False


@pytest.mark.asyncio
async def test_central_llm_database_alert_excludes_unrelated_redis_and_marks_missing_elk(monkeypatch):
    brief = _brief()
    brief["alert_focused_report"] = {
        "reported_service": "GFP_Backend",
        "alert_message": "GFP_Backend database connection errors reached at least 10 events",
        "alert_source": "Zabbix", "family": "database",
        "next_check_fa": "خطاهای دیتابیس در ELK و اتصال واقعی کانفیگ برنامه بررسی شود.",
        "related_checks": [],
        "dependency_extraction_diagnostics": [{
            "matching_endpoint_count": 0,
            "other_dependency_kinds": ["redis", "https"],
            "binding_status": "central_llm_unavailable",
            "config_files_checked": 4,
        }],
        "root_cause_confirmed": False,
    }
    seen = []
    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            seen.append((messages, kwargs))
            return SimpleNamespace(content=(
                "هشدار مربوط به اتصال دیتابیس GFP_Backend است، اما "
                "نتیجه آزمایش مقصد دیتابیس یا لاگ خطای مرتبط تأیید نشده است. "
                "برای تشخیص علت باید ابتدا کانفیگ دیتابیس و لاگ برنامه در "
                "بازه وقوع آلارم بررسی شود."
            ), finish_reason="stop")
    monkeypatch.setattr(focused, "configured_llm_adapter", lambda: Provider())
    out = await focused.explain_alert(brief)
    assert out["status"] == "available"
    user_data = json.loads(seen[0][0][1]["content"])
    assert user_data["reported_service"] == "GFP_Backend"
    assert user_data["family"] == "database"
    assert user_data["log_evidence_status"] == "no_alert_matching_database_log_evidence"
    assert user_data["alert_dependency_coverage"][0]["matching_endpoint_count"] == 0
    assert user_data["alert_dependency_coverage"][0]["other_dependency_kinds"] == ["redis", "https"]
    assert user_data["alert_dependency_coverage"][0]["binding_status"] == "central_llm_unavailable"
    assert user_data["endpoints"] == []
    assert "گمان" not in out["text"]
    assert out["authorizes_execution"] is False
