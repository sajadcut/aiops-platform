from typing import TypedDict, List, Dict, Any, Optional
import asyncio

from langgraph.graph import StateGraph, END

from app.core.logging import logger
from app.llm.base import LLMAdapter
from app.llm.mock_provider import MockLLMProvider
from app.agents.base import AgentInput
from app.agents.triage_agent import TriageAgent
from app.agents.application_agent import ApplicationAgent
from app.agents.infrastructure_agent import InfrastructureAgent
from app.agents.kubernetes_agent import KubernetesAgent
from app.agents.security_agent import SecurityAgent
from app.agents.vm_agent import VMAgent


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
        self.vm_agent = VMAgent(self.llm)

        self.graph = self._build_graph()

    # ------------------------------------------------------------------
    # Graph
    # ------------------------------------------------------------------

    def _build_graph(self):

        workflow = StateGraph(AgentState)

        workflow.add_node(
            "triage",
            self._triage_node
        )

        workflow.add_node(
            "parallel_agents",
            self._parallel_agents_node
        )

        workflow.add_node(
            "synthesize",
            self._synthesize_node
        )

        workflow.add_node(
            "end",
            self._end_node
        )

        workflow.set_entry_point("triage")

        workflow.add_conditional_edges(
            "triage",
            self._route_after_triage,
            {
                "parallel": "parallel_agents",
                "skip": "synthesize",
            },
        )

        workflow.add_edge(
            "parallel_agents",
            "synthesize"
        )

        workflow.add_edge(
            "synthesize",
            "end"
        )

        workflow.add_edge(
            "end",
            END
        )

        return workflow.compile()

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    async def _triage_node(
        self,
        state: AgentState
    ) -> AgentState:

        logger.info(
            "Triage node: Running initial triage"
        )

        state["current_node"] = "triage"

        agent_input = AgentInput(
            incident_id=state.get("incident_id"),
            evidence_summary=state.get(
                "evidence_summary",
                "No evidence provided",
            ),
            service_name=state.get("service_name"),
            context=state.get("context", {}),
        )

        result = await self.triage_agent.analyze(
            agent_input
        )

        state["triage_result"] = result.model_dump()

        state["messages"] = (
            state.get("messages", [])
            + [
                f"Triage: {result.statement[:200]}"
            ]
        )

        state["findings"] = (
            state.get("findings", [])
            + [result.model_dump()]
        )

        return state

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def _route_after_triage(
        self,
        state: AgentState
    ) -> str:

        triage = state.get(
            "triage_result",
            {}
        )

        finding_type = triage.get(
            "finding_type",
            "triage_unknown",
        )

        incident_type = (
            finding_type.replace(
                "triage_",
                ""
            )
            if finding_type.startswith("triage_")
            else "unknown"
        )

        if incident_type in [
            "application",
            "infrastructure",
            "kubernetes",
            "security",
            "vm",
        ]:

            logger.info(
                f"Routing to parallel agents "
                f"for type: {incident_type}"
            )

            return "parallel"

        logger.info(
            f"No specific type detected "
            f"({incident_type}), skipping "
            f"parallel agents"
        )

        return "skip"

    # ------------------------------------------------------------------
    # Specialized Agents
    # ------------------------------------------------------------------

    async def _parallel_agents_node(
        self,
        state: AgentState
    ) -> AgentState:

        logger.info(
            "Parallel agents node: "
            "Running specialized agents"
        )

        state["current_node"] = (
            "parallel_agents"
        )

        agent_input = AgentInput(
            incident_id=state.get("incident_id"),
            evidence_summary=state.get(
                "evidence_summary",
                "No evidence provided",
            ),
            service_name=state.get("service_name"),
            context=state.get("context", {}),
        )

        tasks = [
            self.application_agent.analyze(
                agent_input
            ),
            self.infrastructure_agent.analyze(
                agent_input
            ),
            self.kubernetes_agent.analyze(
                agent_input
            ),
            self.security_agent.analyze(
                agent_input
            ),
            self.vm_agent.analyze(
                agent_input
            ),
        ]

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        findings = []

        for result in results:

            if isinstance(result, Exception):

                logger.error(
                    f"Agent failed: {str(result)}"
                )

                findings.append(
                    {
                        "agent": "error",
                        "error": str(result),
                        "confidence": 0.0,
                        "evidence_ids": [],
                    }
                )

            else:

                findings.append(
                    result.model_dump()
                )

        state["analysis_results"] = findings

        state["findings"] = (
            state.get("findings", [])
            + findings
        )

        state["messages"] = (
            state.get("messages", [])
            + [
                "Parallel analysis completed "
                f"with {len(findings)} findings"
            ]
        )

        return state

    # ------------------------------------------------------------------
    # Evidence extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_evidence(
        state: AgentState
    ) -> Dict[str, Any]:

        context = state.get(
            "context",
            {}
        )

        evidence = context.get(
            "evidence",
            []
        )

        evidence_text = []

        evidence_ids = []

        database_signals = []
        deployment_signals = []
        http_error_signals = []

        for item in evidence:

            if not isinstance(item, dict):
                continue

            evidence_id = (
                item.get("reference")
                or item.get("id")
            )

            if evidence_id:
                evidence_ids.append(
                    str(evidence_id)
                )

            evidence_type = str(
                item.get(
                    "type",
                    "unknown"
                )
            )

            raw_data = item.get(
                "raw_data",
                {}
            )

            if isinstance(raw_data, dict):

                message = (
                    raw_data.get("message")
                    or raw_data.get("name")
                    or raw_data.get("value")
                    or raw_data.get("exception")
                    or str(raw_data)
                )

            else:

                message = str(raw_data)

            message = str(message)

            evidence_text.append(
                f"[{evidence_type}] {message}"
            )

            normalized = message.lower()

            if any(
                term in normalized
                for term in [
                    "database",
                    "connection timeout",
                    "connection refused",
                    "connection pool",
                    "db latency",
                ]
            ):
                database_signals.append(
                    message
                )

            if any(
                term in normalized
                for term in [
                    "deployment",
                    "deployed",
                    "version",
                ]
            ):
                deployment_signals.append(
                    message
                )

            if any(
                term in normalized
                for term in [
                    "http 500",
                    "500 error",
                    "error_rate",
                    "error rate",
                ]
            ):
                http_error_signals.append(
                    message
                )

        return {
            "evidence": evidence,
            "evidence_text": evidence_text,
            "evidence_ids": evidence_ids,
            "database_signals": database_signals,
            "deployment_signals": deployment_signals,
            "http_error_signals": http_error_signals,
        }

    # ------------------------------------------------------------------
    # Evidence-based RCA
    # ------------------------------------------------------------------

    def _build_evidence_based_rca(
        self,
        state: AgentState
    ) -> Optional[Dict[str, Any]]:

        context = state.get(
            "context",
            {}
        )

        incident = context.get(
            "incident",
            {}
        )

        summary = context.get(
            "summary",
            {}
        )

        collected = self._collect_evidence(
            state
        )

        evidence_text = " ".join(
            collected["evidence_text"]
        ).lower()

        incident_summary = str(
            incident.get(
                "summary",
                ""
            )
        ).lower()

        combined_text = (
            incident_summary
            + " "
            + evidence_text
        )

        database_signals = (
            collected["database_signals"]
        )

        deployment_signals = (
            collected["deployment_signals"]
        )

        http_error_signals = (
            collected["http_error_signals"]
        )

        has_http_error = bool(
            http_error_signals
        )

        has_database_signal = bool(
            database_signals
        )

        has_deployment_signal = bool(
            deployment_signals
        )

        error_rate = summary.get(
            "error_rate"
        )

        avg_cpu = summary.get(
            "avg_cpu"
        )

        avg_memory = summary.get(
            "avg_memory"
        )

        # --------------------------------------------------------------
        # Strong database RCA
        # --------------------------------------------------------------

        if (
            has_http_error
            and has_database_signal
        ):

            root_cause = (
                "Database connectivity or "
                "connection-pool saturation is "
                "the most likely root cause of "
                "the HTTP 500 error spike."
            )

            evidence_refs = []

            if http_error_signals:
                evidence_refs.append(
                    "HTTP 500/error-rate evidence"
                )

            if database_signals:
                evidence_refs.append(
                    "Database connectivity evidence"
                )

            if has_deployment_signal:
                evidence_refs.append(
                    "Recent deployment evidence"
                )

            recommendations = [
                (
                    "Inspect database connection-pool "
                    "saturation and active connections"
                ),
                (
                    "Review database latency and "
                    "connection timeout errors"
                ),
            ]

            if has_deployment_signal:
                recommendations.append(
                    (
                        "Compare the current deployment "
                        "with the previous version"
                    )
                )

            if error_rate is not None:
                if float(error_rate) > 10:
                    recommendations.append(
                        (
                            "Investigate the elevated "
                            f"error rate ({float(error_rate):.1f}%)"
                        )
                    )

            confidence = 0.88

            statement = (
                "Evidence indicates that database "
                "connectivity or connection-pool "
                "saturation is the most likely "
                "root cause of the HTTP 500 spike."
            )

            return {
                "agent_name": "rca_engine",
                "finding_type": "root_cause",
                "statement": statement,
                "confidence": confidence,
                "evidence_ids": (
                    collected["evidence_ids"]
                ),
                "recommendations": recommendations,
                "requires_approval": True,
                "root_cause": root_cause,
                "evidence": evidence_refs,
                "metrics": {
                    "error_rate": error_rate,
                    "avg_cpu": avg_cpu,
                    "avg_memory": avg_memory,
                },
            }

        # --------------------------------------------------------------
        # Deployment-related HTTP error
        # --------------------------------------------------------------

        if (
            has_http_error
            and has_deployment_signal
        ):

            root_cause = (
                "The incident is strongly correlated "
                "with a recent application deployment. "
                "The available evidence is insufficient "
                "to prove that the deployment is the "
                "sole root cause."
            )

            return {
                "agent_name": "rca_engine",
                "finding_type": "root_cause",
                "statement": root_cause,
                "confidence": 0.78,
                "evidence_ids": (
                    collected["evidence_ids"]
                ),
                "recommendations": [
                    (
                        "Compare current application "
                        "behavior with the previous version"
                    ),
                    (
                        "Review deployment logs and "
                        "application exceptions"
                    ),
                ],
                "requires_approval": True,
                "root_cause": root_cause,
                "evidence": [
                    "HTTP 500/error-rate evidence",
                    "Recent deployment evidence",
                ],
                "metrics": {
                    "error_rate": error_rate,
                    "avg_cpu": avg_cpu,
                    "avg_memory": avg_memory,
                },
            }

        # --------------------------------------------------------------
        # HTTP errors without sufficient RCA evidence
        # --------------------------------------------------------------

        if has_http_error:

            return {
                "agent_name": "rca_engine",
                "finding_type": "root_cause",
                "statement": (
                    "Application-level HTTP errors "
                    "are confirmed, but the available "
                    "evidence is insufficient to "
                    "establish a single root cause."
                ),
                "confidence": 0.60,
                "evidence_ids": (
                    collected["evidence_ids"]
                ),
                "recommendations": [
                    "Review application logs",
                    (
                        "Correlate errors with recent "
                        "deployments"
                    ),
                    (
                        "Inspect downstream dependencies"
                    ),
                ],
                "requires_approval": True,
                "root_cause": (
                    "Unknown application failure. "
                    "Additional evidence is required."
                ),
                "evidence": [
                    "HTTP 500/error-rate evidence"
                ],
                "metrics": {
                    "error_rate": error_rate,
                    "avg_cpu": avg_cpu,
                    "avg_memory": avg_memory,
                },
            }

        # --------------------------------------------------------------
        # No sufficient evidence
        # --------------------------------------------------------------

        return None

    # ------------------------------------------------------------------
    # Synthesis
    # ------------------------------------------------------------------

    async def _synthesize_node(
        self,
        state: AgentState
    ) -> AgentState:

        logger.info(
            "Synthesize node: "
            "Building evidence-based RCA"
        )

        state["current_node"] = (
            "synthesize"
        )

        rca = self._build_evidence_based_rca(
            state
        )

        if rca:

            state["findings"] = (
                state.get("findings", [])
                + [rca]
            )

            root_cause = rca.get(
                "root_cause",
                rca.get(
                    "statement",
                    "Unknown",
                ),
            )

            recommendations = rca.get(
                "recommendations",
                [],
            )

            evidence = rca.get(
                "evidence",
                [],
            )

            metrics = rca.get(
                "metrics",
                {},
            )

            recommendation_text = "\n".join(
                f"- {item}"
                for item in recommendations
            )

            evidence_text = "\n".join(
                f"- {item}"
                for item in evidence
            )

            state["final_plan"] = (
                "ROOT CAUSE\n"
                f"{root_cause}\n\n"
                "CONFIDENCE\n"
                f"{rca['confidence']:.2f}\n\n"
                "EVIDENCE\n"
                f"{evidence_text or '- No evidence references'}\n\n"
                "METRICS\n"
                f"- Error Rate: {metrics.get('error_rate', 'N/A')}\n"
                f"- Average CPU: {metrics.get('avg_cpu', 'N/A')}\n"
                f"- Average Memory: {metrics.get('avg_memory', 'N/A')}\n\n"
                "RECOMMENDED ACTIONS\n"
                f"{recommendation_text or '- Manual investigation required'}\n\n"
                "EXECUTION POLICY\n"
                "No action has been executed. "
                "Human approval is required before "
                "any operational change."
            )

            state["confidence"] = float(
                rca["confidence"]
            )

            state["messages"] = (
                state.get("messages", [])
                + [
                    "Evidence-based RCA completed"
                ]
            )

            logger.info(
                "Evidence-based RCA completed "
                f"with confidence={rca['confidence']}"
            )

            return state

        # --------------------------------------------------------------
        # LLM fallback
        # --------------------------------------------------------------

        all_findings = state.get(
            "findings",
            []
        )

        triage = state.get(
            "triage_result",
            {}
        )

        prompt = f"""
You are a senior AIOps RCA analyst.

Analyze the incident using ONLY the provided evidence.

Triage Result:
{triage}

Findings:
{all_findings}

Operational Context:
{state.get("context", {})}

Produce:

1. Root Cause Summary
2. Evidence supporting the root cause
3. Confidence from 0 to 1
4. Observed metrics
5. Recommended actions
6. Whether human approval is required

Rules:

- Do not invent evidence.
- Do not claim that an action was executed.
- Do not claim that verification succeeded.
- If evidence is insufficient, explicitly say so.
"""

        try:

            response = await self.llm.generate(
                prompt,
                temperature=0.2,
            )

            state["final_plan"] = (
                response.content
            )

            state["messages"] = (
                state.get("messages", [])
                + [
                    "LLM RCA synthesis completed"
                ]
            )

        except Exception as exc:

            logger.error(
                f"Synthesis failed: {str(exc)}"
            )

            state["final_plan"] = (
                "RCA synthesis failed. "
                "Manual review required."
            )

            state["confidence"] = 0.0

        return state

    # ------------------------------------------------------------------
    # End
    # ------------------------------------------------------------------

    async def _end_node(
        self,
        state: AgentState
    ) -> AgentState:

        logger.info(
            "Workflow completed successfully"
        )

        state["current_node"] = "end"

        state["messages"] = (
            state.get("messages", [])
            + [
                "Workflow completed"
            ]
        )

        return state

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run(
        self,
        initial_state: Dict[str, Any]
    ) -> Dict[str, Any]:

        result = await self.graph.ainvoke(
            initial_state
        )

        return result