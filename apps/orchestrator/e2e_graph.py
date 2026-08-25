"""Production-oriented end-to-end incident workflow.

Context -> Agents -> RCA -> Evaluator -> Decision -> Approval/Execution ->
Verification -> Audit/Memory. Agents never execute tools directly.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, TypedDict, cast
from uuid import UUID

from langgraph.graph import END, StateGraph

from agents.application import ApplicationAgent
from agents.infrastructure import InfrastructureAgent
from agents.kubernetes import KubernetesAgent
from agents.security import SecurityAgent
from agents.shared.base import AgentInput, AgentOutput
from agents.triage import TriageAgent
from agents.vm import VMAgent
from apps.approval_service import ApprovalService
from apps.audit_service import AuditService
from apps.context_service.evidence_collector import EvidenceCollector
from apps.evaluator.gate import EvaluationGate
from apps.decision_engine import DecisionAction, DecisionEngine
from apps.execution_service import ExecutionRequest, ExecutionService
from apps.memory_service import OperationalMemoryService
from apps.rag_service import KnowledgeRAGService
from apps.verification_service import VerificationEngine
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.elasticsearch.client import ElasticsearchClient
from integrations.llm.base import LLMAdapter
from integrations.llm.mock_provider import MockLLMProvider
from integrations.prometheus.client import PrometheusClient
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.zabbix.connector import ZabbixConnector
from integrations.zabbix.client import MockZabbixClient


class E2EState(TypedDict, total=False):
    messages: List[str]
    current_node: str
    incident_id: Optional[str]
    service_name: Optional[str]
    evidence_summary: str
    context: Dict[str, Any]
    findings: List[Dict[str, Any]]
    analysis_results: List[Dict[str, Any]]
    triage_result: Dict[str, Any]
    final_plan: str
    confidence: float
    knowledge_results: List[Dict[str, Any]]
    memory_results: List[Dict[str, Any]]
    live_evidence: Dict[str, Any]
    evaluation: Dict[str, Any]
    decision: Dict[str, Any]
    approval: Dict[str, Any]
    execution_request: Dict[str, Any]
    execution_result: Dict[str, Any]
    verification_result: Dict[str, Any]
    before_context: Dict[str, Any]
    after_context: Dict[str, Any]
    terminal_reason: Optional[str]


class E2EOrchestrator:
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None, db: Any = None):
        if llm_adapter is None and settings.APP_ENV == "production":
            raise RuntimeError("production_llm_adapter_required")
        self.llm = llm_adapter or MockLLMProvider()
        self.db = db
        self.triage_agent = TriageAgent(self.llm)
        self.application_agent = ApplicationAgent(self.llm)
        self.infrastructure_agent = InfrastructureAgent(self.llm)
        self.kubernetes_agent = KubernetesAgent(self.llm)
        self.security_agent = SecurityAgent(self.llm)
        self.vm_agent = VMAgent(self.llm)

        zabbix = MockZabbixClient() if settings.APP_ENV != "production" else ZabbixConnector()
        vm_connector = SSHVMConnector() if settings.SSH_ENABLED else None
        self.vm_connector = vm_connector
        self.evidence_collector = EvidenceCollector(
            zabbix=zabbix,
            elasticsearch=ElasticsearchClient(),
            prometheus=PrometheusClient(),
            vm=vm_connector,
        )
        self.graph = self._build_graph()

    def _build_graph(self):
        w = StateGraph(E2EState)
        w.add_node("context", self._context_node)
        w.add_node("triage", self._triage_node)
        w.add_node("parallel_agents", self._parallel_agents_node)
        w.add_node("rca", self._rca_node)
        w.add_node("evaluator", self._evaluator_node)
        w.add_node("decision", self._decision_node)
        w.add_node("approval", self._approval_node)
        w.add_node("execution", self._execution_node)
        w.add_node("verification", self._verification_node)
        w.add_node("memory", self._memory_node)
        w.add_node("end", self._end_node)
        w.set_entry_point("context")
        w.add_edge("context", "triage")
        w.add_edge("triage", "parallel_agents")
        w.add_edge("parallel_agents", "rca")
        w.add_edge("rca", "evaluator")
        w.add_conditional_edges("evaluator", self._route_after_evaluation, {"decision": "decision", "stop": "end"})
        w.add_conditional_edges("decision", self._route_after_decision, {"approval": "approval", "execute": "execution", "stop": "end"})
        w.add_conditional_edges("approval", self._route_after_approval, {"execute": "execution", "stop": "end"})
        w.add_edge("execution", "verification")
        w.add_edge("verification", "memory")
        w.add_edge("memory", "end")
        w.add_edge("end", END)
        return w.compile()

    async def run(self, state: E2EState) -> E2EState:
        result = cast(E2EState, await self.graph.ainvoke(state))
        if not result.get("terminal_reason") and not result.get("execution_result"):
            result["terminal_reason"] = "workflow_completed_without_execution"
        return result

    @staticmethod
    def _audit(event_type: str, state: E2EState, **metadata: Any) -> None:
        AuditService.record(
            event_type=event_type,
            actor="e2e_orchestrator",
            incident_id=state.get("incident_id"),
            action=state.get("execution_request", {}).get("action"),
            status="recorded",
            metadata=metadata,
        )

    async def _context_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "context"
        context = dict(state.get("context", {}))
        service = state.get("service_name") or context.get("service") or "unknown"
        state["knowledge_results"] = []
        state["memory_results"] = []
        if self.db is not None:
            query = str(context.get("incident", {}).get("summary") or state.get("evidence_summary") or service)
            try:
                state["knowledge_results"] = await KnowledgeRAGService(self.db).search(query, limit=5, min_similarity=0.5)
            except Exception as exc:
                logger.warning(f"RAG retrieval failed: {exc}")
            try:
                state["memory_results"] = await OperationalMemoryService(self.db).search_similar(query, service_scope=service, limit=5, min_similarity=0.5)
            except Exception as exc:
                logger.warning(f"Memory retrieval failed: {exc}")
        try:
            since = datetime.now(timezone.utc) - timedelta(minutes=15)
            state["live_evidence"] = await self.evidence_collector.collect(service, since)
        except Exception as exc:
            logger.warning(f"Live evidence collection failed: {exc}")
            state["live_evidence"] = {"service": service, "evidence": [], "error": str(exc)}

        context["knowledge_results"] = state["knowledge_results"]
        context["memory_results"] = state["memory_results"]
        context["live_evidence"] = state["live_evidence"]
        context["evidence"] = state["live_evidence"].get("evidence", [])
        state["context"] = context
        if not state.get("before_context"):
            state["before_context"] = {"live_evidence": state["live_evidence"]}
        self._audit("context_loaded", state, knowledge_count=len(state["knowledge_results"]), memory_count=len(state["memory_results"]), evidence_count=len(state["live_evidence"].get("evidence", [])))
        return state

    async def _triage_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "triage"
        result = await self.triage_agent.analyze(AgentInput(incident_id=state.get("incident_id"), evidence_summary=state.get("evidence_summary", "No evidence provided"), service_name=state.get("service_name"), context=state.get("context", {})))
        data = result.model_dump()
        state["triage_result"] = data
        state["findings"] = state.get("findings", []) + [data]
        self._audit("triage_completed", state, confidence=data.get("confidence"))
        return state

    async def _parallel_agents_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "parallel_agents"
        inp = AgentInput(incident_id=state.get("incident_id"), evidence_summary=state.get("evidence_summary", "No evidence provided"), service_name=state.get("service_name"), context=state.get("context", {}))
        results = await asyncio.gather(self.application_agent.analyze(inp), self.infrastructure_agent.analyze(inp), self.kubernetes_agent.analyze(inp), self.security_agent.analyze(inp), self.vm_agent.analyze(inp), return_exceptions=True)
        findings: List[Dict[str, Any]] = []
        for result in results:
            if isinstance(result, Exception):
                findings.append({"agent": "error", "error": str(result), "confidence": 0.0, "evidence_ids": []})
            else:
                findings.append(cast(AgentOutput, result).model_dump())
        state["analysis_results"] = findings
        state["findings"] = state.get("findings", []) + findings
        self._audit("parallel_analysis_completed", state, finding_count=len(findings))
        return state

    async def _rca_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "rca"
        prompt = "Analyze only supplied operational evidence. Return root cause, evidence references, confidence and recommended action plan. Never claim execution.\n" + f"Triage={state.get('triage_result', {})}\nFindings={state.get('findings', [])}\nContext={state.get('context', {})}"
        try:
            state["final_plan"] = (await self.llm.generate(prompt, temperature=0.2)).content
        except Exception as exc:
            state["final_plan"] = "Manual investigation required: RCA generation failed."
            logger.error(f"RCA generation failed: {exc}")
        state["confidence"] = self._average_confidence(state.get("findings", []))
        self._audit("rca_completed", state, confidence=state["confidence"])
        return state

    async def _evaluator_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "evaluator"
        result = EvaluationGate.evaluate(state.get("findings", []), state.get("final_plan", ""))
        state["evaluation"] = result
        self._audit("evaluation_completed", state, **result)
        return state

    def _route_after_evaluation(self, state: E2EState) -> str:
        result = state.get("evaluation", {})
        if result.get("approved_for_decision"):
            return "decision"
        state["terminal_reason"] = result.get("reason", "evaluation_failed")
        self._audit("decision_blocked_by_evaluator", state, reason=state["terminal_reason"])
        return "stop"

    async def _decision_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "decision"
        result = DecisionEngine.evaluate_plan(state.get("final_plan", ""), state.get("findings", []))
        state["decision"] = result.model_dump(mode="json")
        self._audit("decision_made", state, decision=result.action.value, risk=result.risk_level.value, reason=result.reason)
        return state

    def _route_after_decision(self, state: E2EState) -> str:
        decision = state.get("decision", {})
        if not state.get("execution_request"):
            state["terminal_reason"] = "No explicit execution request supplied"
            return "stop"
        action = decision.get("action")
        if action == DecisionAction.REQUIRE_APPROVAL.value:
            return "approval"
        if action == DecisionAction.AUTO_EXECUTE.value:
            return "execute"
        state["terminal_reason"] = f"Decision action is {action or 'unknown'}"
        return "stop"

    async def _approval_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "approval"
        decision = state.get("decision", {})
        request = ApprovalService.create_request(incident_id=state.get("incident_id") or "unknown", action=state.get("execution_request", {}).get("action", "unknown"), risk_level=str(decision.get("risk_level", "unknown")), approver=str(decision.get("suggested_approver") or "Team-Lead"), metadata={"reason": decision.get("reason"), "workflow": "e2e"})
        state["approval"] = request
        return state

    def _route_after_approval(self, state: E2EState) -> str:
        approval = state.get("approval", {})
        if approval.get("status") == "approved":
            return "execute"
        state["terminal_reason"] = "approval_required"
        return "stop"

    async def _execution_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "execution"
        request_data = dict(state.get("execution_request", {}))
        request = ExecutionRequest(**request_data)
        result = await ExecutionService.execute(request)
        state["execution_result"] = result.model_dump()
        self._audit("execution_completed", state, success=result.success, blocked=result.execution_blocked)
        return state

    async def _verification_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "verification"
        before = dict(state.get("before_context") or {})
        after = dict(state.get("after_context") or {})
        if not after:
            service = state.get("service_name") or "unknown"
            try:
                since = datetime.now(timezone.utc) - timedelta(minutes=5)
                after["live_evidence"] = await self.evidence_collector.collect(service, since)
                state["after_context"] = after
            except Exception as exc:
                logger.warning(f"Post-execution evidence collection failed: {exc}")
                after = {}
        result = await VerificationEngine.verify_action(action_plan=state.get("final_plan", ""), service=state.get("service_name") or "unknown", before_context=before, after_context=after)
        state["verification_result"] = result.model_dump(mode="json")
        state.setdefault("context", {})["post_execution_evidence"] = after.get("live_evidence", {})
        self._audit("verification_completed", state, status=result.status.value, confidence=result.confidence, evidence_count=len(after.get("live_evidence", {}).get("evidence", [])))
        return state

    async def _memory_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "memory"
        verification = state.get("verification_result", {})
        status = str(verification.get("status", "inconclusive"))
        outcome = verification.get("message")
        persisted = False
        if self.db is not None and status != "inconclusive" and outcome:
            incident_uuid: Optional[UUID] = None
            incident_id = state.get("incident_id")
            if incident_id:
                try:
                    incident_uuid = UUID(str(incident_id))
                except ValueError:
                    incident_uuid = None
            try:
                triage = state.get("triage_result", {})
                root_cause = triage.get("likely_cause") or triage.get("summary") or state.get("final_plan")
                evidence_refs: List[str] = []
                for finding in state.get("findings", []):
                    evidence_refs.extend(str(ref) for ref in finding.get("evidence_ids", []) if ref)
                await OperationalMemoryService(self.db).add_entry(pattern=state.get("evidence_summary", "incident pattern"), symptoms={"findings": state.get("findings", []), "evidence_refs": sorted(set(evidence_refs))}, root_cause=root_cause, action=state.get("final_plan"), verification_result=status, outcome=outcome, environment=settings.APP_ENV, service_scope=state.get("service_name") or "unknown", incident_id=incident_uuid)
                persisted = True
            except Exception as exc:
                logger.error(f"Operational memory write-back failed: {exc}")
                self._audit("memory_writeback_failed", state, error=str(exc))
        self._audit("memory_writeback", state, persisted=persisted, verification_status=status)
        return state

    async def _end_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "end"
        if not state.get("terminal_reason") and not state.get("execution_result"):
            state["terminal_reason"] = "workflow_completed_without_execution"
        return state

    @staticmethod
    def _average_confidence(findings: List[Dict[str, Any]]) -> float:
        values = [float(item.get("confidence", 0.0)) for item in findings if item.get("confidence") is not None]
        return sum(values) / len(values) if values else 0.0
