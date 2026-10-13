"""First-pass AIOps dynamic reasoning acceptance: advisory only, fail closed."""
import json
from types import SimpleNamespace

import pytest

from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner


ERROR = (
    '2026/10/13 [warn] the "user" directive ignored in /etc/nginx/nginx.conf:43\n'
    '2026/10/13 [emerg] unexpected "{" in /etc/nginx/nginx.conf:103\n'
    'nginx: configuration file /etc/nginx/nginx.conf test failed'
)


def config_evidence(*, valid=False, success=True, supported=True):
    return {
        "type": "telemetry", "source": "vm_mcp", "reference": "validator-1",
        "raw_data": {
            "diagnostic": "config_validate", "target": "10.1.2.3",
            "service": "nginx", "success": success, "supported": supported,
            "valid": valid, "detail": ERROR,
        },
    }


def incident(*, evidence=None):
    return {
        "incident_id": "incident-123", "service_name": "nginx",
        "analysis_results": [{"agent_name": "vm", "finding_type": "vm_analysis"}],
        "coordination": {"missing_evidence": ["Current config excerpt"]},
        "knowledge_results": [{"source_id": "cognia:previous", "content": "historical syntax notes"}],
        "context": {"evidence": evidence if evidence is not None else [config_evidence()]},
    }


class RAG:
    def __init__(self):
        self.calls = []

    async def search(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return [{
            "source_id": "cognia:focused", "relevance": 0.77,
            "content": "Vendor documentation is advisory; validate actual proposed changes",
        }]


class LLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def generate_with_messages(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_focused_requery_after_live_error_not_just_alert_title():
    state, rag = incident(), RAG()
    result = await DynamicInvestigationPlanner.enrich_knowledge(state, rag=rag)
    assert result["status"] == "retrieved"
    assert result["count"] == 1
    assert result["source_refs"] == ["cognia:focused"]
    assert "unexpected" in rag.calls[0][0]
    assert rag.calls[0][1]["phase"] == "knowledge_rag_followup"
    assert [r["source_id"] for r in state["knowledge_results"]][:2] == [
        "cognia:focused", "cognia:previous",
    ]
    assert result["counts_as_live_evidence"] is False
    assert state.get("execution_request") is None
    repeat = await DynamicInvestigationPlanner.enrich_knowledge(state, rag=rag)
    assert repeat["status"] == "already_queried"
    assert len(rag.calls) == 1


@pytest.mark.asyncio
async def test_requery_respects_subject_scoping_and_never_falls_back_to_unscoped():
    state = incident()
    state["context"]["knowledge_subject"] = {"namespace": "tenant", "externalSubjectId": ""}
    rag = RAG()
    result = await DynamicInvestigationPlanner.enrich_knowledge(state, rag=rag)
    assert result["status"] == "scope_unavailable"
    assert not rag.calls


@pytest.mark.asyncio
async def test_live_valid_config_supersedes_old_error():
    state = incident(evidence=[config_evidence(), config_evidence(valid=True)])
    assert DynamicInvestigationPlanner.confirmed_config_failure(state["context"]["evidence"]) is None
    assert DynamicInvestigationPlanner.search_query(
        service="nginx", evidence=state["context"]["evidence"], findings=[]
    ) == ""
    assert (await DynamicInvestigationPlanner.enrich_knowledge(state, rag=RAG()))["status"] == "not_needed"


@pytest.mark.asyncio
async def test_proposal_questions_need_actual_config_and_cannot_claim_patch_or_validation():
    llm = LLM([SimpleNamespace(content='{"checks":["service_logs","config_validate"],"question":"Can you provide a reviewed configuration revision?"}', finish_reason="stop")])
    state = incident()
    result = await DynamicInvestigationPlanner.propose(state, adapter=llm)
    assert result["model_status"] == "structured"
    assert result["checks"] == ["service_logs", "config_validate"]
    assert len(result["operator_questions"]) == 2
    proposal = result["config_proposal"]
    assert proposal["status"] == "needs_read_only_config"
    assert proposal["validation_status"] == "UNVERIFIED"
    assert proposal["validator_executed_on_proposal"] is False
    assert proposal["current_configuration"] is None
    assert proposal["proposed_configuration"] is None
    assert proposal["unified_diff"] is None
    assert result["execution_authority"] is False
    assert state.get("execution_request") is None


@pytest.mark.asyncio
async def test_malicious_llm_tool_selection_is_rejected_and_targets_not_delegated():
    llm = LLM([SimpleNamespace(
        content=json.dumps({
            "checks": ["ssh -c rm -rf /", "start_service", "restart_service",
                       "config_validate", "config_validate", "unknown"],
            "target": "another-host", "command": "delete backups",
            "question": "Review source configuration?",
        }), finish_reason="stop",
    )])
    result = await DynamicInvestigationPlanner.propose(incident(), adapter=llm)
    assert result["checks"] == ["config_validate"]
    requests = DynamicInvestigationPlanner.evidence_requests(
        result, has_service=True, has_port=False,
    )
    assert requests == [{
        "evidence_type": "telemetry", "reason": "configuration syntax validation",
        "preferred_source": "vm",
    }]
    assert result["execution_authority"] is False
    assert all("target" not in request and "command" not in request for request in requests)


@pytest.mark.asyncio
async def test_truncated_model_retries_with_bounded_tokens_not_silent_zero():
    llm = LLM([
        SimpleNamespace(content='{"checks":', finish_reason="length"),
        SimpleNamespace(content='{"checks":["service_status"],"question":""}', finish_reason="stop"),
    ])
    result = await DynamicInvestigationPlanner.propose(incident(), adapter=llm)
    assert len(llm.calls) == 2
    assert llm.calls[0][1]["max_tokens"] < llm.calls[1][1]["max_tokens"]
    assert result["checks"] == ["service_status"]
    assert result["model_status"] == "structured"
    assert result["operator_questions"]


@pytest.mark.asyncio
async def test_double_model_failure_keeps_operator_question_without_faking_fix():
    llm = LLM([
        SimpleNamespace(content="{", finish_reason="length"),
        SimpleNamespace(content="{", finish_reason="length"),
    ])
    result = await DynamicInvestigationPlanner.propose(incident(), adapter=llm)
    assert result["model_status"] == "truncated"
    assert result["operator_questions"]
    assert result["checks"] == []
    assert result["config_proposal"]["validation_status"] == "UNVERIFIED"


def test_only_explicit_vm_read_only_capabilities_are_requested():
    commands = {"checks": ["service_status", "port_listener_status", "config_validate", "start_service"]}
    requests = DynamicInvestigationPlanner.evidence_requests(
        commands, has_service=True, has_port=False,
    )
    assert len(requests) == 2
    assert all(row["preferred_source"] == "vm" for row in requests)
    assert "start_service" not in str(requests)
