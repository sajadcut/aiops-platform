"""One deterministic identity authority across ingestion, live MCP and ContextBuilder."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from apps.context_service import ContextBuilder
from apps.context_service.knowledge_topology import KnowledgeTopologyResolver
from apps.context_service.service_identity import ServiceIdentityResolver
from apps.context_service.llm_identity import (
    consult_operational_unknowns, detect_operational_unknowns, suggest_from_llm,
)
from apps.remediation_planner import RemediationPlanner
from domain.contracts.config import settings
from domain.schemas import IncidentCreate


NGINX_DOC = {
    "source_id": "cognia:unrelated:nginx",
    "content": "Service: nginx\nPlatform: VM\nOwner: ops",
    "relevance": 0.4,
}
WEB_DOC = {
    "source_id": "cognia:domain:web",
    "content": "Service: web-api\nURL: https://web.wepod.ir\nPlatform: Kubernetes",
    "relevance": 12.5,
}


class FakeRAG:
    def __init__(self, results):
        self.results = results

    async def search(self, *args, **kwargs):
        return list(self.results)


class FakeCollector:
    def __init__(self, service=None):
        self.service = service
        self.queries = []

    async def collect(self, name, since, until=None):
        self.queries.append(name)
        return {
            "service": self.service,
            "since": since.isoformat(),
            "until": None,
            "asset_context": {"service": self.service, "hostname": "monitor-host"},
            "evidence": [],
        }


@pytest.mark.asyncio
async def test_general_memory_alert_does_not_inherit_incidental_nginx_from_cognia():
    collector = FakeCollector()
    context = await ContextBuilder(
        collector=collector, rag_service=FakeRAG([NGINX_DOC]),
    ).build_context(IncidentCreate(
        source="zabbix", severity="medium",
        summary="High memory utilization on APORSDTNKSA0101",
        context={"host": "APORSDTNKSA0101"},
    ))
    assert collector.queries == ["unknown"]
    assert context["service"] == "unknown"
    assert context["service_identity"]["status"] == "unknown"
    assert context["service_identity"]["verified"] is False
    assert context["service_identity"]["suspected_service"] == "nginx"
    assert context["asset_context"]["service"] is None
    assert context["topology_context"]["unverified_knowledge_service_hint"] == "nginx"
    assert context["knowledge_status"]["status"] == "available"


@pytest.mark.asyncio
async def test_unrelated_mcp_nginx_on_host_does_not_rename_memory_alert():
    collector = FakeCollector(service="nginx")
    result = await ContextBuilder(
        collector=collector, rag_service=FakeRAG([]),
    ).build_context(IncidentCreate(
        source="zabbix", severity="high",
        summary="High memory utilization on host APORSDTNKSA0101",
        context={"host": "APORSDTNKSA0101"},
    ))
    assert collector.queries == ["unknown"]
    assert result["service"] == "unknown"
    assert result["asset_context"]["service"] is None
    assert result["service_identity"]["status"] == "unknown"
    assert result["service_identity"]["basis"] == "live_service_unlinked_to_alert"
    assert result["service_identity"]["suspected_service"] == "nginx"
    assert result["service_identity"]["suspected_service_source"] == "mcp_observation"
    assert result["service_identity"]["verified"] is False


def test_conflicting_mcp_name_and_exact_cognia_fqdn_stays_unknown():
    doc = KnowledgeTopologyResolver.resolve([WEB_DOC], expected_fqdns=["web.wepod.ir"])
    result = ServiceIdentityResolver.resolve(
        source_service=None,
        live_asset={"service": "nginx"},
        knowledge_topology=doc,
        expected_fqdns=["web.wepod.ir"],
    )
    assert result["service"] == "unknown"
    assert result["service_identity"]["status"] == "unknown"
    assert result["service_identity"]["suspected_service"] == "web-api"
    assert result["service_identity"]["conflicts"]
    assert result["topology_context"]["requires_live_verification"] is True


@pytest.mark.asyncio
async def test_exact_source_fqdn_still_enables_service_scoped_diagnostics_but_is_not_verified():
    collector = FakeCollector()
    result = await ContextBuilder(
        collector=collector, rag_service=FakeRAG([WEB_DOC]),
    ).build_context(IncidentCreate(
        source="zabbix", severity="medium",
        summary='Download speed for "web.wepod.ir" has slowed down',
    ))
    assert collector.queries == ["web-api"]
    assert result["service"] == "web-api"
    assert result["service_identity"]["status"] == "suspected"
    assert result["service_identity"]["verified"] is False
    assert result["service_identity"]["requires_more_evidence"] is True
    assert result["topology_context"]["requires_live_verification"] is True


@pytest.mark.asyncio
async def test_explicit_service_beats_unrelated_cognia_and_is_reported_not_verified():
    collector = FakeCollector()
    result = await ContextBuilder(
        collector=collector, rag_service=FakeRAG([NGINX_DOC]),
    ).build_context(IncidentCreate(
        source="prometheus", severity="high", service="payment-api",
        summary="Payment latency high",
    ))
    assert collector.queries == ["payment-api"]
    assert result["service"] == "payment-api"
    assert result["service_identity"]["status"] == "reported"
    assert result["service_identity"]["verified"] is False
    assert result["asset_context"]["service"] == "payment-api"


def test_live_mcp_verifies_only_source_declared_service_at_exact_source_target():
    row = {
        "source": "vm_mcp", "type": "telemetry", "reference": "vm:service:1",
        "raw_data": {"diagnostic": "service_status", "target": "10.100.6.199",
                     "service": "nginx", "active_state": "inactive", "supported": True},
    }
    assert ServiceIdentityResolver.independently_verified(
        expected_service="nginx", expected_target="10.100.6.199",
        evidence=[row],
    )
    for bad in [
        {**row, "raw_data": {**row["raw_data"], "target": "10.100.6.200"}},
        {**row, "source": "zabbix"},
        {**row, "raw_data": {**row["raw_data"], "service": "postgresql"}},
        {**row, "raw_data": {**row["raw_data"], "success": False}},
        {**row, "raw_data": {**row["raw_data"], "diagnostic": "process_snapshot"}},
    ]:
        assert not ServiceIdentityResolver.independently_verified(
            expected_service="nginx", expected_target="10.100.6.199", evidence=[bad]
        )


def test_disagreement_between_source_and_mcp_is_explicit_and_blocks_write():
    result = ServiceIdentityResolver.resolve(
        source_service="payment-api",
        live_asset={"service": "nginx"},
        knowledge_topology={},
        expected_fqdns=[],
    )
    assert result["service"] == "payment-api"
    assert result["service_identity"]["verified"] is False
    assert result["service_identity"]["conflicts"]
    state = {
        "evaluation": {"approved_for_decision": True},
        "context": {
            "service_identity": result["service_identity"],
            "trigger_signal": {
                "source": "zabbix",
                "service": "payment-api",
                "raw_data": {"target_ip": "10.100.6.199"},
            },
            "evidence": [],
        },
    }
    plan = RemediationPlanner.plan(state)
    assert plan["status"] == "not_planned"
    assert plan["reason"] == "service_identity_conflict_requires_review"


def test_generic_alert_even_with_unrelated_inactive_nginx_cannot_auto_plan():
    evidence = [{
        "type": "telemetry", "source": "vm_mcp", "reference": "vm:s1",
        "raw_data": {"diagnostic": "service_status", "target": "10.100.6.199",
                     "service": "nginx", "active_state": "inactive"},
    }]
    for status in ("unknown", "observed"):
        plan = RemediationPlanner.plan({
            "evaluation": {"approved_for_decision": True},
            "context": {
                "service_identity": {
                    "status": status, "service": "unknown" if status == "unknown" else "nginx",
                    "verified": False, "conflicts": [],
                },
                "trigger_signal": {
                    "source": "zabbix", "service": None,
                    "summary": "High memory utilization", "raw_data": {"target_ip": "10.100.6.199"},
                },
                "evidence": evidence,
            },
        })
        assert plan["status"] == "not_planned"
        assert plan["reason"] == "service_identity_unverified_for_automatic_planning"


@pytest.mark.asyncio
async def test_llm_can_only_suggest_candidate_from_actual_mcp_and_never_change_identity(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "http://internal-llm")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")
    logs = []

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            logs.append((messages, kwargs))
            return SimpleNamespace(
                content='{"service":"nginx","reason":"May warrant investigation"}',
                finish_reason="stop",
            )

    evidence = [{
        "source": "vm_mcp", "type": "telemetry", "reference": "live:1",
        "raw_data": {"diagnostic": "service_status", "service": "nginx",
                     "target": "10.100.6.199", "active_state": "inactive"},
    }]
    result = await suggest_from_llm(
        summary="High memory utilization", evidence=evidence, adapter=Provider()
    )
    assert result["status"] == "hypothesis"
    assert result["verified"] is False
    assert result["execution_authority"] is False
    assert result["service"] == "nginx"
    assert result["evidence_refs"] == ["live:1"]
    assert len(logs) == 1
    assert logs[0][1]["temperature"] == 0.0
    resolution = ServiceIdentityResolver.resolve(
        source_service=None, live_asset={}, knowledge_topology={},
        candidate_hypotheses=[result],
    )
    assert resolution["service"] == "unknown"
    assert resolution["service_identity"]["suspected_service"] == "nginx"
    assert resolution["service_identity"]["suspected_service_source"] == "llm_hypothesis"
    assert not resolution["service_identity"]["verified"]


@pytest.mark.asyncio
async def test_llm_hallucination_and_no_diagnostic_candidates_are_rejected(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai-compatible")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "http://internal-llm")
    monkeypatch.setattr(settings, "LLM_MODEL", "internal-model")

    class Provider:
        async def generate_with_messages(self, messages, **kwargs):
            return SimpleNamespace(content='{"service":"postgresql"}', finish_reason="stop")

    candidates = [{
        "source": "vm_mcp", "type": "telemetry", "reference": "live:1",
        "raw_data": {"service": "nginx", "diagnostic": "service_status"},
    }]
    assert (await suggest_from_llm(
        summary="CPU high", evidence=candidates, adapter=Provider()
    ))["status"] == "unsubstantiated"
    assert (await suggest_from_llm(
        summary="CPU high", evidence=[], adapter=Provider()
    ))["status"] == "no_diagnostic_candidates"


def test_identity_has_bounded_provenance_in_snapshot_and_persian_ui():
    from pathlib import Path
    brief = Path("apps/decision_brief.py").read_text(encoding="utf-8")
    ui = Path("dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert '"service_identity": service_identity_display' in brief
    assert "suspectedService:'سرویس احتمالی (تأیید نشده)'" in ui
    assert "source_declared_service:'Tag یا فیلد معتبر آلارم'" in ui
    assert "status(i.service_identity?.status)" in ui


def test_operational_unknown_detector_handles_any_unverified_service_config():
    evidence = [
        {"source": "vm_mcp", "reference": "config-1", "raw_data": {
            "diagnostic": "config_validate", "service": "gfpapi",
            "supported": False, "valid": None,
            "detail": "config_validation_adapter_unavailable",
        }},
        {"source": "vm_mcp", "reference": "config-2", "raw_data": {
            "diagnostic": "config_validate", "service": "nginx",
            "supported": True, "valid": True,
        }},
    ]
    gaps = detect_operational_unknowns(evidence)
    assert len(gaps) == 1
    assert gaps[0]["topic"] == "config_validation_method"
    assert gaps[0]["subject"] == "gfpapi"
    assert gaps[0]["evidence_refs"] == ["config-1"]


@pytest.mark.asyncio
async def test_unknown_guidance_consults_llm_but_never_verifies_or_executes(monkeypatch):
    import json
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai-compatible")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "http://example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")
    calls = []

    class FakeAdapter:
        async def generate_with_messages(self, messages, **kwargs):
            calls.append((messages, kwargs))
            return SimpleNamespace(finish_reason="stop", content=json.dumps({"items": [
                {"topic": "config_validation_method", "subject": "gfpapi",
                 "explanation": "Vendor config test is unknown",
                 "validation_approach": "Read the official service runbook and identify a read-only config test",
                 "uncertainty": "not yet verified"},
                {"topic": "unexpected_extra", "subject": "nginx",
                 "explanation": "unsafe", "validation_approach": "restart the host"},
            ]}))

    gaps = [{"topic": "config_validation_method", "subject": "gfpapi",
             "reason": "config_validation_adapter_unavailable", "evidence_refs": ["cfg-1"]}]
    result = await consult_operational_unknowns(unknowns=gaps, adapter=FakeAdapter())

    assert result["status"] == "suggested"
    assert result["execution_authority"] is False
    assert result["counts_as_evidence"] is False
    assert result["config_validation_passed"] is False
    assert len(result["items"]) == 1
    assert result["items"][0]["verified"] is False
    assert "read-only" in result["items"][0]["validation_approach"]
    assert calls[0][1]["stage"] == "operational_unknown_guidance"
    assert "Do not provide executable shell snippets" in calls[0][0][0]["content"]


@pytest.mark.asyncio
async def test_unknown_guidance_fails_closed_if_model_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai-compatible")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "http://example.invalid")
    monkeypatch.setattr(settings, "LLM_MODEL", "test-model")

    class BrokenAdapter:
        async def generate_with_messages(self, *args, **kwargs):
            raise RuntimeError("simulated LLM timeout")

    gap = {"topic": "config_validation_method", "subject": "unknown-app",
           "reason": "no adapter", "evidence_refs": []}
    response = await consult_operational_unknowns(unknowns=[gap], adapter=BrokenAdapter())
    assert response["status"] == "unavailable"
    assert response["execution_authority"] is False
    assert response["config_validation_passed"] is False
    assert response["items"] == []


@pytest.mark.asyncio
async def test_no_gaps_does_not_call_llm():
    class ShouldNeverCall:
        async def generate_with_messages(self, *args, **kwargs):
            raise AssertionError("LLM must be consulted only for explicit gaps")

    result = await consult_operational_unknowns(unknowns=[], adapter=ShouldNeverCall())
    assert result["status"] == "not_needed"
    assert result["items"] == []


def test_general_unknown_detector_captures_specialist_failure_and_missing_evidence():
    findings = [
        {"agent_name": "application", "finding_type": "application_error",
         "health_status": "unknown", "missing_evidence": ["valid specialist output"]},
    ]
    found = detect_operational_unknowns([], findings)
    assert {x["topic"] for x in found} == {
        "specialist_analysis_unknown", "missing_evidence",
    }
    assert all(x["subject"] == "application" for x in found)


def test_general_unknown_detector_handles_unsupported_vm_diagnostic():
    evidence = [{
        "source": "vm_mcp", "type": "source_observation",
        "reference": "missing-diagnostic",
        "raw_data": {"status": "skipped", "service": "custom-app",
                     "detail": "diagnostic_not_supported"},
    }]
    result = detect_operational_unknowns(evidence)
    assert len(result) == 1
    assert result[0]["topic"] == "diagnostic_method_unknown"
    assert result[0]["evidence_refs"] == ["missing-diagnostic"]



def test_verified_invalid_config_requests_only_advisory_llm_repair_guidance():
    evidence = [{
        "source": "vm_mcp", "reference": "cfg42",
        "raw_data": {
            "diagnostic": "config_validate", "service": "haproxy",
            "success": True, "supported": True, "valid": False,
            "config_file": "/opt/apps/haproxy.cfg", "error_line": 42,
            "syntax_error": "unknown keyword 'foobar'",
        },
    }]
    gaps = detect_operational_unknowns(evidence)
    assert len(gaps) == 1
    assert gaps[0]["topic"] == "config_syntax_repair_guidance"
    assert gaps[0]["subject"] == "haproxy"
    assert "/opt/apps/haproxy.cfg:42" in gaps[0]["reason"]
    # No invented config errors when the VM validator has not been executed.
    evidence[0]["raw_data"]["success"] = False
    assert detect_operational_unknowns(evidence) == []


def test_unknown_config_method_includes_systemd_candidate_without_validating_it():
    evidence = [{
        "source": "vm_mcp", "reference": "cfgUnknown",
        "raw_data": {
            "diagnostic": "config_validate", "service": "gfpapi",
            "success": True, "supported": False, "valid": None,
            "config_file": "/opt/gfpapi/app.yml",
            "config_path_source": "systemd_execstart_unvalidated",
            "detail": "config_validation_adapter_unavailable",
        },
    }]
    gaps = detect_operational_unknowns(evidence)
    assert len(gaps) == 1
    assert gaps[0]["topic"] == "config_validation_method"
    assert "/opt/gfpapi/app.yml" in gaps[0]["reason"]
