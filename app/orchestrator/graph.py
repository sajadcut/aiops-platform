from typing import TypedDict, Literal, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from app.core.logging import logger
from app.llm.base import LLMAdapter
from app.llm.mock_provider import MockLLMProvider
from app.agents.base import AgentInput, AgentOutput
from app.agents.triage_agent import TriageAgent
from app.agents.application_agent import ApplicationAgent
from app.agents.infrastructure_agent import InfrastructureAgent
from app.agents.kubernetes_agent import KubernetesAgent
from app.agents.security_agent import SecurityAgent
from app.agents.vm_agent import VMAgent  # ✅ VM Agent (Guest OS)
import asyncio

class AgentState(TypedDict, total=False):
    messages: List[str]
    current_node: str
    findings: List[Dict[str, Any]]
    confidence: float
    incident_id: Optional[str]
    evidence_summary: str
    service_name: Optional[str]
    context: Dict[str, Any]
    triage_result: Optional[Dict[str, Any]]
    analysis_results: List[Dict[str, Any]]
    final_plan: Optional[str]

class WorkflowOrchestrator:
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or MockLLMProvider()
        self.triage_agent = TriageAgent(self.llm)
        self.application_agent = ApplicationAgent(self.llm)
        self.infrastructure_agent = InfrastructureAgent(self.llm)
        self.kubernetes_agent = KubernetesAgent(self.llm)
        self.security_agent = SecurityAgent(self.llm)
        self.vm_agent = VMAgent(self.llm)          # ✅ VM Agent
        self.graph = self._build_graph()
    
    def _build_graph(self):
        workflow = StateGraph(AgentState)
        
        workflow.add_node("triage", self._triage_node)
        workflow.add_node("parallel_agents", self._parallel_agents_node)
        workflow.add_node("synthesize", self._synthesize_node)
        workflow.add_node("end", self._end_node)
        
        workflow.set_entry_point("triage")
        workflow.add_conditional_edges(
            "triage",
            self._route_after_triage,
            {
                "parallel": "parallel_agents",
                "skip": "synthesize"
            }
        )
        workflow.add_edge("parallel_agents", "synthesize")
        workflow.add_edge("synthesize", "end")
        workflow.add_edge("end", END)
        
        return workflow.compile()
    
    async def _triage_node(self, state: AgentState) -> AgentState:
        logger.info("Triage node: Running initial triage")
        state["current_node"] = "triage"
        
        agent_input = AgentInput(
            incident_id=state.get("incident_id"),
            evidence_summary=state.get("evidence_summary", "No evidence provided"),
            service_name=state.get("service_name"),
            context=state.get("context", {})
        )
        
        result = await self.triage_agent.analyze(agent_input)
        state["triage_result"] = result.model_dump()
        state["messages"] = state.get("messages", []) + [f"Triage: {result.statement[:100]}..."]
        state["findings"] = state.get("findings", []) + [result.model_dump()]
        
        return state
    
    def _route_after_triage(self, state: AgentState) -> str:
        triage = state.get("triage_result", {})
        finding_type = triage.get("finding_type", "triage_unknown")
        incident_type = finding_type.replace("triage_", "") if finding_type.startswith("triage_") else "unknown"
        
        # ✅ پشتیبانی از انواع جدید (شامل vm)
        if incident_type in ["application", "infrastructure", "kubernetes", "security", "vm"]:
            logger.info(f"Routing to parallel agents for type: {incident_type}")
            return "parallel"
        else:
            logger.info(f"No specific type detected ({incident_type}), skipping parallel agents")
            return "skip"
    
    async def _parallel_agents_node(self, state: AgentState) -> AgentState:
        logger.info("Parallel agents node: Running specialized agents")
        state["current_node"] = "parallel_agents"
        
        agent_input = AgentInput(
            incident_id=state.get("incident_id"),
            evidence_summary=state.get("evidence_summary", "No evidence provided"),
            service_name=state.get("service_name"),
            context=state.get("context", {})
        )
        
        # ✅ اجرای موازی ۵ Agent (Application, Infrastructure, Kubernetes, Security, VM)
        tasks = [
            self.application_agent.analyze(agent_input),
            self.infrastructure_agent.analyze(agent_input),
            self.kubernetes_agent.analyze(agent_input),
            self.security_agent.analyze(agent_input),
            self.vm_agent.analyze(agent_input),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        findings = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Agent failed: {str(result)}")
                findings.append({
                    "agent": "error",
                    "error": str(result),
                    "confidence": 0.0
                })
            else:
                findings.append(result.model_dump())
        
        state["analysis_results"] = findings
        state["findings"] = state.get("findings", []) + findings
        state["messages"] = state.get("messages", []) + [f"Parallel analysis completed with {len(findings)} findings"]
        
        return state
    
    async def _synthesize_node(self, state: AgentState) -> AgentState:
        logger.info("Synthesize node: Combining findings")
        state["current_node"] = "synthesize"
        
        all_findings = state.get("findings", [])
        triage = state.get("triage_result", {})
        
        prompt = f"""
        Based on the following findings, create a final incident summary and action plan.
        
        Triage Result: {triage}
        All Findings: {all_findings}
        
        Please provide:
        1. **Root Cause Summary**: What is the most likely root cause?
        2. **Confidence**: Overall confidence (0-1)
        3. **Action Plan**: Prioritized list of actions
        4. **Escalation**: Should this be escalated to humans?
        
        Respond with clear, structured text.
        """
        
        try:
            response = await self.llm.generate(prompt, temperature=0.3)
            state["final_plan"] = response.content
            state["messages"] = state.get("messages", []) + ["Final synthesis completed"]
        except Exception as e:
            logger.error(f"Synthesis failed: {str(e)}")
            state["final_plan"] = f"Synthesis failed: {str(e)}. Manual review required."
        
        return state
    
    async def _end_node(self, state: AgentState) -> AgentState:
        logger.info("Workflow completed successfully")
        state["current_node"] = "end"
        state["messages"] = state.get("messages", []) + ["Workflow completed"]
        return state
    
    async def run(self, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        result = await self.graph.ainvoke(initial_state)
        return result