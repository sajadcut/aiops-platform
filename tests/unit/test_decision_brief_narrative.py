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
async def test_wrong_section_count_is_repaired_once_without_changing_validators(monkeypatch):
    brief = sample_brief()
    brief["snapshot_id"] = "narrative-schema-one-bounded-retry"
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")
    calls = []

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            calls.append(messages)
            payload = valid_rows()
            if len(calls) == 1:
                payload["sections"].pop()
            return SimpleNamespace(
                content=json.dumps(payload, ensure_ascii=False),
                finish_reason="stop",
            )

    monkeypatch.setattr(service, "configured_llm_adapter", lambda: Provider())
    result = await service.generate_narrative(brief, "fa")
    assert result["status"] == "available"
    assert len(result["sections"]) == len(service.SECTIONS)
    assert len(calls) == 2
    assert "CORRECT STRUCTURE" in calls[1][0]["content"]
    assert result["authorizes_execution"] is False


@pytest.mark.asyncio
async def test_citation_policy_violation_does_not_get_retried(monkeypatch):
    brief = sample_brief()
    brief["snapshot_id"] = "narrative-safety-no-retry"
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")
    calls = []

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            calls.append(1)
            payload = valid_rows()
            payload["sections"][0]["citations"] = ["invented-source"]
            return SimpleNamespace(
                content=json.dumps(payload, ensure_ascii=False),
                finish_reason="stop",
            )

    monkeypatch.setattr(service, "configured_llm_adapter", lambda: Provider())
    result = await service.generate_narrative(brief, "fa")
    assert result["status"] == "fallback"
    assert result["validation_code"] == "narrative_reference"
    assert len(calls) == 1


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


def test_large_realistic_incident_has_bounded_grounded_narrative_projection():
    brief = sample_brief()
    brief["source_references"] = [f"durable-evidence-{i}" for i in range(90)]
    brief["agent_findings"] = [
        {
            "agent": f"agent-{i}", "status": "partial", "finding": "Observed: " + "x" * 1500,
            "mission": "Analyze live telemetry", "confidence": 0.6,
            "evidence_refs": [f"durable-evidence-{i}"],
            "tool_diagnostic_blob": "THIS MUST NEVER BE GIVEN TO THE LLM " * 1000,
        } for i in range(50)
    ]
    brief["mcp_evidence"] = [
        {
            "server": "vm-edge", "tool": "service_status",
            "status": "success", "finding": "inactive " + "y" * 1200,
            "evidence_ref": f"durable-evidence-{i}",
            "raw_secret": "hidden-credential",
        } for i in range(70)
    ]
    brief["cognia_knowledge"]["items"] = [
        {"source_id": f"cognia:{i}", "use_status": "not_verified", "relevance": 0.5}
        for i in range(60)
    ]
    brief["missing_evidence"] = ["prometheus_unavailable"]
    brief["remediation_recommendation"] = {
        "action": "start_service", "tool": "ssh_vm", "target": "vm-staging",
        "risk_level": "high",
    }
    encoded = service.bounded_projection_json(brief)
    assert encoded is not None
    assert len(encoded) <= 18000
    obj = json.loads(encoded)
    assert obj["remediation"]["target"] == "vm-staging"
    assert obj["remediation"]["action"] == "start_service"
    assert obj["source_counts"]["agents_total"] == 50
    assert obj["source_counts"]["mcp_observations_total"] == 70
    assert len(obj["agents"]) < 50
    assert len(obj["mcp_observations"]) < 70
    assert "hidden-credential" not in encoded
    assert "THIS MUST NEVER" not in encoded
    assert obj["missing_evidence"] == ["prometheus_unavailable"]


@pytest.mark.asyncio
async def test_large_incident_calls_llm_instead_of_unconditional_size_fallback(monkeypatch):
    brief = sample_brief()
    brief["snapshot_id"] = "large-incident-bounded-projection"
    brief["agent_findings"] = [
        {"agent": f"sre-{i}", "status": "partial",
         "finding": "observed issue " + ("a" * 2600),
         "evidence_refs": ["evidence-1"]}
        for i in range(22)
    ]
    brief["mcp_evidence"] = [
        {"server": "vm", "tool": "service_status",
         "finding": "inactive " + ("b" * 2000),
         "evidence_ref": "evidence-1"}
        for _ in range(24)
    ]
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")
    calls = []

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            calls.append(messages)
            return SimpleNamespace(
                content=json.dumps(valid_rows(), ensure_ascii=False),
                finish_reason="stop",
            )

    monkeypatch.setattr(service, "configured_llm_adapter", lambda: Provider())
    outcome = await service.generate_narrative(brief, "fa")
    assert outcome["status"] == "available"
    assert outcome["authorizes_execution"] is False
    assert len(calls) == 1
    assert len(calls[0][1]["content"]) < 18500



def test_llm_cannot_override_verified_invalid_appsettings_as_healthy():
    brief = sample_brief()
    brief["configuration_diagnostic"] = {
        "status": "invalid", "config_file": "/data/gfp/gfpapi/appsettings.json",
        "error_line": 32, "error_column": 3,
        "error_code": "json_property_name",
    }
    fake = valid_rows()
    fake["sections"][1]["text"] = (
        "طبق بررسی، ساختار JSON سالم است و هیچ خطایی در appsettings وجود ندارد."
    )
    with pytest.raises(ValueError, match="narrative_conflicts_with_live_config_validator"):
        service.validate_narrative(json.dumps(fake, ensure_ascii=False), brief, "fa")
    # A truthful warning is not blocked just because it mentions validation.
    fake["sections"][1]["text"] = (
        "ساختار JSON معتبر نیست و فایل appsettings در خط ۳۲ باید بررسی شود."
    )
    assert len(service.validate_narrative(
        json.dumps(fake, ensure_ascii=False), brief, "fa")) == len(service.SECTIONS)


def test_ai_narrative_receives_stop_attribution_and_conditional_start_options():
    brief = sample_brief()
    brief["incident_summary"]["service"] = "gfpapi"
    brief["technical_investigation"] = {
        "stop_origin": {
            "status": "possible_unverified",
            "note_fa": "Stop دستی یا خودکار؛ هنوز اثبات نشده",
            "manual_stop_proven": False,
            "indicators": ["Termination signal=SIGKILL", "TimeoutStop=90s"],
            "evidence_refs": ["evidence-1"],
            "next_check_fa": "مطابقت audit و journal",
        },
        "domains": [
            {"key": "systemd", "technical_result": "ActiveState=failed; Result=timeout", "status": "investigated"},
        ],
        "rca": {"cause_confirmed": False, "likely_hypotheses": [
            {"title": "Stop/Restart manual or automated", "check": "Review audit and journal",
             "supporting": ["evidence-1"]},
        ]},
    }
    brief["recovery_advisory"] = {
        "suggested_action": "restart_service", "target": "10.248.16.82",
        "configuration_validation": "UNVERIFIED", "authorizes_execution": False,
        "alternative_actions": [
            {"action": "start_service", "status": "alternative_not_runbook_authorized_for_failed"},
        ],
        "prerequisite_checks": ["Audit maintenance stop", "Validate runtime before any write"],
        "evidence_refs": ["evidence-1"],
    }
    projected = service.projection(brief)
    assert projected["technical_diagnosis"]["stop_origin"]["manual_stop_proven"] is False
    assert projected["technical_diagnosis"]["stop_origin"]["indicators"][0] == "Termination signal=SIGKILL"
    assert projected["conditional_recovery"]["suggested_action"] == "restart_service"
    assert projected["conditional_recovery"]["authorizes_execution"] is False
    assert projected["conditional_recovery"]["alternative_actions"][0]["action"] == "start_service"
    assert len(service.bounded_projection_json(brief)) <= 18000


def test_narrative_accepts_fenced_json_without_relaxing_citation_validation():
    fenced = chr(96) * 3
    raw = fenced + "json\n" + json.dumps(valid_rows(), ensure_ascii=False) + "\n" + fenced
    parsed = service.validate_narrative(raw, sample_brief(), "fa")
    assert len(parsed) == len(service.SECTIONS)
    bad = valid_rows()
    bad["sections"][0]["citations"] = ["fictional-ref"]
    with pytest.raises(ValueError, match="narrative_reference"):
        service.validate_narrative(
            fenced + "json\n" + json.dumps(bad, ensure_ascii=False) + "\n" + fenced,
            sample_brief(), "fa",
        )


def test_live_sized_config_review_retains_approval_blocker_and_exact_target():
    """Regression: 40+ observations and long citations must not hide the RCA.

    The original compactor trimmed agent/MCP items but kept the full citation
    catalogue and 40 evidence-gap/conflict strings; the operator then saw
    brief_too_large instead of the review/validation explanation.
    """
    brief = sample_brief()
    brief["source_references"] = [
        f"evidence-{n}-" + ("reference" * 15) for n in range(120)
    ]
    brief["mcp_evidence"] = [
        {"server": "vm-edge", "tool": "config_validate", "status": "success",
         "finding": 'unexpected "{" in /etc/nginx/nginx.conf:103',
         "evidence_ref": brief["source_references"][n]}
        for n in range(40)
    ]
    brief["missing_evidence"] = [
        f"missing-evidence-{n}-" + ("needs independent verification " * 8)
        for n in range(40)
    ]
    brief["evidence_conflicts"] = [
        f"conflict-{n}-" + ("independently unverified " * 8)
        for n in range(40)
    ]
    brief["configuration_diagnostic"] = {
        "status": "invalid", "config_file": "/etc/nginx/nginx.conf",
        "error_line": 103, "syntax_error": 'unexpected "{"',
    }
    brief["remediation_recommendation"] = {
        "action": "apply_configuration_change", "tool": "ssh_vm",
        "target": "10.248.16.82", "risk_level": "high",
    }
    brief["approval_readiness"] = {
        "status": "pending_validation", "action": "apply_configuration_change",
        "target": "10.248.16.82", "rollback_supported": True,
    }
    output = service.bounded_projection_json(brief)
    assert output is not None
    assert len(output) <= 18000
    payload = json.loads(output)
    assert payload["source_counts"]["evidence_references_total"] == 120
    assert payload["source_counts"]["missing_evidence_total"] == 40
    assert payload["source_counts"]["conflicts_total"] == 40
    assert len(payload["allowed_evidence_references"]) < 120
    assert len(payload["missing_evidence"]) < 40
    assert payload["config_diagnostic"]["config_file"] == "/etc/nginx/nginx.conf"
    assert payload["config_diagnostic"]["error_line"] == 103
    assert payload["approval"]["status"] == "pending_validation"
    assert payload["remediation"]["action"] == "apply_configuration_change"
    assert payload["remediation"]["target"] == "10.248.16.82"


def test_invalid_configuration_is_explicit_in_fallback_without_llm():
    brief = sample_brief()
    brief["configuration_diagnostic"] = {
        "status": "invalid",
        "config_file": "/etc/nginx/nginx.conf",
        "error_line": 103,
        "syntax_error": 'unexpected "{"',
    }
    result = service.fallback(brief, "fa", "model_output_invalid")
    assert result["status"] == "fallback"
    assert "/etc/nginx/nginx.conf" in result["summary"]
    assert "۱۰۳" in result["summary"] or "103" in result["summary"]
    assert 'unexpected "{"' in result["summary"]
    assert "اعتبارسنجی مستقل" in result["summary"]
    assert "تأیید انسانی" in result["summary"]
    assert result["authorizes_execution"] is False
    # The model failure cannot silently turn an invalid configuration healthy.
    assert "نامعتبر" in result["summary"]


def test_fallback_does_not_invent_configuration_failure_without_evidence():
    brief = sample_brief()
    result = service.fallback(brief, "fa", "model_timeout")
    assert result["summary"] == brief["localized_narrative"]["fa"]


@pytest.mark.asyncio
async def test_bad_llm_narrative_reports_safe_specific_validation_code(monkeypatch):
    brief = sample_brief()
    brief["snapshot_id"] = "bad-json-safe-code"
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")

    class InvalidProvider:
        async def generate_with_messages(self, messages, **kwargs):
            return SimpleNamespace(content="not-json PRIVATE_DO_NOT_EXPOSE",
                                   finish_reason="stop")

    monkeypatch.setattr(service, "configured_llm_adapter",
                        lambda: InvalidProvider())
    result = await service.generate_narrative(brief, "fa")
    assert result["status"] == "fallback"
    assert result["reason"] == "model_output_invalid"
    assert result["validation_code"] == "narrative_json_invalid"
    assert "PRIVATE_DO_NOT_EXPOSE" not in str(result)
    assert result["authorizes_execution"] is False
