"""End-to-end AIOps incident orchestration.

The graph composes the repository's existing analysis, decision, approval,
execution, verification, audit and memory contracts. Agents never execute
operational actions directly.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, TypedDict, cast

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
from apps.decision_engine import DecisionAction, DecisionEngine
from apps.execution_service import ExecutionRequest, ExecutionResult, ExecutionService
from apps.memory_service import OperationalMemoryService
from apps.rag_service import KnowledgeRAGService
from apps.verification_service import VerificationEngine, VerificationResult
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter
from integrations.llm.mock_provider import MockLLMProvider


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
        self.llm = llm_adapter or MockLLMProvider()
        self.db = db
        self.triage_agent = TriageAgent(self.llm)
        self.application_agent = ApplicationAgent(self.llm)
        self.infrastructure_agent = InfrastructureAgent(self.llm)
        self.kubernetes_agent = KubernetesAgent(self.llm)
        self.security_agent = SecurityAgent(self.llm)
        self.vm_agent = VMAgent(self.llm)
        self.graph = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(E2EState)
        workflow.add_node("context", self._context_node)
        workflow.add_node("triage", self._triage_node)
        workflow.add_node("parallel_agents", self._parallel_agents_node)
        workflow.add_node("rca", self._rca_node)
        workflow.add_node("decision", self._decision_node)
        workflow.add_node("approval", self._approval_node)
        workflow.add_node("execution", self._execution_node)
        workflow.add_node("verification", self._verification_node)
        workflow.add_node("memory", self._memory_node)
        workflow.add_node("end", self._end_node)
        workflow.set_entry_point("context")
        workflow.add_edge("context", "triage")
        workflow.add_edge("triage", "parallel_agents")
        workflow.add_edge("parallel_agents", "rca")
        workflow.add_edge("rca", "decision")
        workflow.add_conditional_edges("decision", self._route_after_decision, {"approval": "approval", "execute": "execution", "stop": "end"})
        workflow.add_conditional_edges("approval", self._route_after_approval, {"execute": "execution", "stop": "end"})
        workflow.add_edge("execution", "verification")
        workflow.add_edge("verification", "memory")
        workflow.add_edge("memory", "end")
        workflow.add_edge("end", END)
        return workflow.compile()

    def _audit(self, event_type: str, state: E2EState, status: str = "recorded", **metadata: Any) -> None:
        AuditService.record(
            event_type=event_type,
            actor="e2e_orchestrator",
            incident_id=state.get("incident_id"),
            action=state.get("execution_request", {}).get("action"),
            status=status,
            metadata=metadata,
        )

    async def _context_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "context"
        context = state.get("context", {})
        incident = context.get("incident", {})
        query = str(incident.get("summary") or state.get("evidence_summary") or state.get("service_name") or "operational incident")
        state["knowledge_results"] = []
        state["memory_results"] = []
        if self.db is not None:
            try:
                state["knowledge_results"] = await KnowledgeRAGService(self.db).search(query, limit=5, min_similarity=0.5)
            except Exception as exc:
                logger.error(f"RAG retrieval failed: {exc}")
            try:
                state["memory_results"] = await OperationalMemoryService(self.db).search_similar(query, service_scope=state.get("service_name"), limit=5, min_similarity=0.5)
            except Exception as exc:
                logger.error(f"Operational memory retrieval failed: {exc}")
        enriched = dict(context)
        enriched["knowledge_results"] = state["knowledge_results"]
        enriched["memory_results"] = state["memory_results"]
        state["context"] = enriched
        state["messages"] = state.get("messages", []) + ["Context, RAG and memory retrieval completed"]
        self._audit("context_loaded", state, knowledge_count=len(state["knowledge_results"]), memory_count=len(state["memory_results"]))
        return state

    async def _triage_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "triage"
        result = await self.triage_agent.analyze(AgentInput(incident_id=state.get("incident_id"), evidence_summary=state.get("evidence_summary", "No evidence provided"), service_name=state.get("service_name"), context=state.get("context", {})))
        data = result.model_dump()
        state["triage_result"] = data
        state["findings"] = state.get("findings", []) + [data]
        state["messages"] = state.get("messages", []) + [f"Triage: {result.statement[:200]}"]
        self._audit("triage_completed", state, confidence=data.get("confidence"))
        return state

    async def _parallel_agents_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "parallel_agents"
        agent_input = AgentInput(incident_id=state.get("incident_id"), evidence_summary=state.get("evidence_summary", "No evidence provided"), service_name=state.get("service_name"), context=state.get("context", {}))
        results = await asyncio.gather(self.application_agent.analyze(agent_input), self.infrastructure_agent.analyze(agent_input), self.kubernetes_agent.analyze(agent_input), self.security_agent.analyze(agent_input), self.vm_agent.analyze(agent_input), return_exceptions=True)
        findings: List[Dict[str, Any]] = []
        for result in results:
            if isinstance(result, Exception):
                findings.append({"agent": "error", "error": str(result), "confidence": 0.0})
            else:
                findings.append(cast(AgentOutput, result).model_dump())
        state["analysis_results"] = findings
        state["findings"] = state.get("findings", []) + findings
        state["messages"] = state.get("messages", []) + [f"Parallel analysis completed with {len(findings)} findings"]
        self._audit("parallel_analysis_completed", state, finding_count=len(findings))
        return state

    async def _rca_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "rca"
        findings = state.get("findings", [])
        triage = state.get("triage_result", {})
        prompt = "You are an AIOps RCA analyst. Use only supplied evidence.\n" f"Triage: {triage}\n" f"Findings: {findings}\n" f"Context: {state.get('context', {})}\n" "Return root cause, evidence, confidence, and a recommended action plan. Never claim an action was executed."
        try:
            response = await self.llm.generate(prompt, temperature=0.2)
            state["final_plan"] = response.content
        except Exception as exc:
            logger.error(f"RCA generation failed: {exc}")
            state["final_plan"] = "RCA generation failed; manual investigation required."
        state["confidence"] = self._average_confidence(findings)
        state["messages"] = state.get("messages", []) + ["RCA completed"]
        self._audit("rca_completed", state, confidence=state["confidence"])
        return state

    async def _decision_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "decision"
        result = DecisionEngine.evaluate_plan(state.get("final_plan", ""), state.get("findings", []))
        state["decision"] = result.model_dump(mode="json")
        state["messages"] = state.get("messages", []) + [f"Decision: {result.action.value} / {result.risk_level.value}"]
        self._audit("decision_made", state, decision=result.action.value, risk=result.risk_level.value, reason=result.reason)
        return state

    def _route_after_decision(self, state: E2EState) -> str:
        decision = state.get("decision", {})
        action = decision.get("action")
        if not state.get("execution_request"):
            state["terminal_reason"] = "No explicit execution request supplied"
            self._audit("execution_blocked", state, reason=state["terminal_reason"])
            return "stop"
        if action == DecisionAction.REQUIRE_APPROVAL.value:
            return "approval"
        if action == DecisionAction.AUTO_EXECUTE.value:
            return "execute"
        state["terminal_reason"] = f"Decision action is {action or 'unknown'}"
        self._audit("execution_blocked", state, reason=state["terminal_reason"])
        return "stop"

    async def _approval_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "approval"
        decision = state.get("decision", {})
        request = ApprovalService.create_request(incident_id=state.get("incident_id") or "unknown", action=state.get("execution_request", {}).get("action", "unknown"), risk_level=str(decision.get("risk_level", "unknown")), approver=str(decision.get("suggested_approver") or "Team-Lead"), metadata={"reason": decision.get("reason"), "workflow": "e2e"})
        state["approval"] = request
        state["messages"] = state.get("messages", []) + [f"Approval requested: {request['approval_id']}"]
        self._audit("approval_requested", state, approval_id=request["approval_id"], approver=request["approver"])
        return state

    def _route_after_approval(self, state: E2EState) -> str:
        approval_id = state.get("approval", {}).get("approval_id")
        if approval_id and ApprovalService.is_approved(approval_id):
            self._audit("approval_granted", state, approval_id=approval_id)
            return "execute"
        state["terminal_reason"] = "Approval is pending or rejected"
        self._audit("approval_not_granted", state, approval_id=approval_id, reason=state["terminal_reason"])
        return "stop"

    async def _execution_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "execution"
        payload = dict(state.get("execution_request", {}))
        approval_id = state.get("approval", {}).get("approval_id")
        approved = bool(approval_id and ApprovalService.is_approved(approval_id))
        request = ExecutionRequest(tool_name=str(payload.get("tool_name", "")), action=str(payload.get("action", "")), target=str(payload.get("target", "")), parameters=dict(payload.get("parameters", {})), timeout=int(payload.get("timeout", 30)), agent_name="e2e_orchestrator", approval_granted=approved or state.get("decision", {}).get("action") == DecisionAction.AUTO_EXECUTE.value, approval_id=approval_id)
        result: ExecutionResult = await ExecutionService.execute(request)
        state["execution_result"] = result.model_dump(mode="json")
        state["messages"] = state.get("messages", []) + [f"Execution completed: success={result.success}, blocked={result.execution_blocked}"]
        self._audit("execution_completed", state, success=result.success, blocked=result.execution_blocked, reason=result.reason, error=result.error)
        return state

    async def _verification_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "verification"
        result: VerificationResult = await VerificationEngine.verify_action(action_plan=str(state.get("execution_request", {}).get("action", state.get("final_plan", ""))), service=str(state.get("service_name") or "unknown"), before_context=state.get("before_context") or state.get("context", {}), after_context=state.get("after_context"))
        state["verification_result"] = result.model_dump(mode="json")
        state["messages"] = state.get("messages", []) + [f"Verification: {result.status.value}"]
        self._audit("verification_completed", state, verification_status=result.status.value, confidence=result.confidence)
        return state

    async def _memory_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "memory"
        if self.db is None:
            state["terminal_reason"] = "Memory write skipped: no DB session"
            self._audit("memory_write_skipped", state, reason=state["terminal_reason"])
            return state
        verification = state.get("verification_result", {})
        request = state.get("execution_request", {})
        try:
            await OperationalMemoryService(self.db).add_entry(pattern=state.get("evidence_summary", "incident")[:500], symptoms=state.get("context", {}).get("summary", {}), root_cause=state.get("final_plan"), action=request.get("action"), verification_result=str(verification.get("status", "inconclusive")), outcome=verification.get("message"), environment=state.get("context", {}).get("environment"), service_scope=state.get("service_name"), incident_id=state.get("incident_id"))
            state["messages"] = state.get("messages", []) + ["Operational memory updated"]
            self._audit("memory_written", state, verification_status=verification.get("status"))
        except Exception as exc:
            logger.error(f"Operational memory write failed: {exc}")
            state["messages"] = state.get("messages", []) + ["Operational memory update failed"]
            self._audit("memory_write_failed", state, error=str(exc))
        return state

    async def _end_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "end"
        reason = state.get("terminal_reason")
        state["messages"] = state.get("messages", []) + [f"Workflow completed{': ' + reason if reason else ''}"]
        self._audit("workflow_completed", state, terminal_reason=reason)
        return state

    @staticmethod
    def _average_confidence(findings: List[Dict[str, Any]]) -> float:
        values = [float(item["confidence"]) for item in findings if isinstance(item, dict) and isinstance(item.get("confidence"), (int, float))]
        return sum(values) / len(values) if values else 0.0

    async def run(self, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        return await self.graph.ainvoke(cast(E2EState, initial_state))
