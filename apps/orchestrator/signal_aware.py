from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from agents.shared.telemetry import AgentTelemetry
from apps.context_service.asset_identity import AssetIdentityResolver
from apps.decision_engine import DecisionEngine
from apps.execution_service.tools.registry import tool_registry
from apps.orchestrator.e2e_graph import E2EOrchestrator, E2EState
from domain.contracts.config import settings
from domain.contracts.logging import logger


class SignalAwareE2EOrchestrator(E2EOrchestrator):
    """Collaborative E2E workflow for source-triggered and API-triggered incidents.

    It preserves initiating Evidence and exposes structured peer findings,
    consensus, contradictions and evidence requests to subsequent specialist
    passes. Agents do not free-chat; collaboration happens through audited
    Incident state. Peer findings are context, not new Evidence.
    """

    async def _context_node(self, state: E2EState) -> E2EState:
        initial_context = dict(state.get("context") or {})
        trigger_evidence = [
            item for item in initial_context.get("trigger_evidence", [])
            if isinstance(item, dict)
        ]
        trigger_signal = initial_context.get("trigger_signal")

        state = await super()._context_node(state)
        context = dict(state.get("context") or {})
        collected = list(context.get("evidence") or [])

        merged: Dict[str, Dict[str, Any]] = {}
        for item in trigger_evidence + collected:
            if not isinstance(item, dict):
                continue
            key = str(
                item.get("evidence_id")
                or item.get("id")
                or item.get("reference")
                or item.get("source_id")
                or f"{item.get('source')}:{item.get('type')}:{len(merged)}"
            )
            merged[key] = item

        merged_evidence = list(merged.values())
        service_hint = state.get("service_name") or context.get("service")
        asset_context = AssetIdentityResolver.resolve(merged_evidence, service_hint)
        resolved_service = asset_context.get("service") or service_hint
        if resolved_service:
            state["service_name"] = str(resolved_service)
            context["service"] = str(resolved_service)

        live = dict(state.get("live_evidence") or {})
        live["evidence"] = merged_evidence
        live["asset_context"] = asset_context
        context["evidence"] = merged_evidence
        context["live_evidence"] = live
        context["asset_context"] = asset_context
        if trigger_signal is not None:
            context["trigger_signal"] = trigger_signal
        context["trigger_evidence"] = trigger_evidence
        state["live_evidence"] = live
        state["context"] = context

        self._audit(
            "trigger_evidence_merged",
            state,
            trigger_count=len(trigger_evidence),
            total_evidence_count=len(merged_evidence),
            trigger_source=(trigger_signal or {}).get("source") if isinstance(trigger_signal, dict) else None,
            asset_type=asset_context.get("asset_type"),
            platform=asset_context.get("platform"),
        )
        return state

    @staticmethod
    def _publish_peer_context(state: E2EState, findings: list[Dict[str, Any]], coordination: Dict[str, Any]) -> None:
        context = state.setdefault("context", {})
        peer_context = {
            "policy": "peer_findings_are_auxiliary_context_not_live_evidence",
            "findings": findings,
            "coordination": {
                "confidence": coordination.get("confidence"),
                "agreement_score": coordination.get("agreement_score"),
                "disagreement": coordination.get("disagreement"),
                "contradictions": coordination.get("contradictions", []),
                "consensus_hypotheses": coordination.get("consensus_hypotheses", []),
                "missing_evidence": coordination.get("missing_evidence", []),
                "evidence_requests": coordination.get("evidence_requests", []),
                "handoff_agents": coordination.get("handoff_agents", []),
            },
        }
        context["peer_findings"] = findings
        context["agent_coordination"] = peer_context["coordination"]
        summary = dict(context.get("summary") or {})
        summary["peer_operational_context"] = peer_context
        context["summary"] = summary

    async def _parallel_agents_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "parallel_agents"
        routing = state.get("routing") or self.coordinator.select_agents(
            state.get("triage_result", {}), self.registry.enabled_names()
        )
        selected = list(routing.get("selected", []))

        findings = await self._run_specialists(selected, state)
        coordination = self.coordinator.synthesize(findings)
        self._publish_peer_context(state, findings, coordination)

        requested_handoffs = [
            name for name in coordination.get("handoff_agents", [])
            if name not in selected and self.registry.get(name) is not None
        ]
        if requested_handoffs:
            second = await self._run_specialists(requested_handoffs, state)
            findings.extend(second)
            selected.extend(requested_handoffs)
            coordination = self.coordinator.synthesize(findings)
            self._publish_peer_context(state, findings, coordination)
            self._audit("agent_handoff_completed", state, handoff_agents=requested_handoffs)

        evidence_requests = list(coordination.get("evidence_requests") or [])
        if evidence_requests and await self._additional_evidence_round(state, evidence_requests):
            self._publish_peer_context(state, findings, coordination)
            refreshed = await self._run_specialists(selected, state)
            findings = refreshed
            coordination = self.coordinator.synthesize(findings)
            self._publish_peer_context(state, findings, coordination)

        for finding in findings:
            name = str(finding.get("agent_name") or "unknown")
            if name == "unknown":
                continue
            AgentTelemetry.record_result(
                name,
                confidence=float(finding.get("confidence", 0) or 0),
                evidence_coverage=float(finding.get("evidence_coverage", 0) or 0),
                disagreement=bool(coordination.get("disagreement")),
                conflict_count=len(coordination.get("contradictions") or []),
                human_review=bool(finding.get("requires_human_review")),
            )

        state["analysis_results"] = findings
        state["findings"] = [state.get("triage_result", {})] + findings
        state["coordination"] = coordination
        state["routing"] = {
            **routing,
            "selected": selected,
            "skipped": sorted(set(self.registry.enabled_names()).difference(selected)),
        }
        self._audit(
            "specialist_analysis_completed",
            state,
            selected_agents=selected,
            skipped_agents=state["routing"]["skipped"],
            finding_count=len(findings),
            disagreement=coordination.get("disagreement"),
            contradictions=coordination.get("contradictions", []),
            agreement_score=coordination.get("agreement_score"),
            consensus_hypotheses=coordination.get("consensus_hypotheses", []),
            evidence_requests=coordination.get("evidence_requests", []),
            evidence_rounds=state.get("evidence_rounds", 1),
            peer_context_shared=True,
        )
        return state

    async def _decision_node(self, state: E2EState) -> E2EState:
        """Bind deterministic policy to the concrete tool/action/target request."""
        state["current_node"] = "decision"
        request = dict(state.get("execution_request") or {})
        tool = tool_registry.get_tool(str(request.get("tool_name") or "")) if request else None
        result = DecisionEngine.evaluate_plan(
            state.get("final_plan", ""),
            state.get("findings", []),
            execution_request=request or None,
            tool_risk_level=tool.risk_level if tool is not None else None,
            tool_requires_approval=bool(tool.requires_approval) if tool is not None else False,
            tool_exists=(tool is not None) if request else True,
        )
        state["decision"] = result.model_dump(mode="json")
        self._audit(
            "decision_made",
            state,
            decision=result.action.value,
            risk=result.risk_level.value,
            reason=result.reason,
            policy_metadata=result.metadata,
        )
        return state

    async def _execution_node(self, state: E2EState) -> E2EState:
        """Refresh the verification baseline immediately before a write/read tool call.

        Approval may be granted minutes after initial analysis, so the initial
        Incident context is not a trustworthy before-state for verification.
        A failed refresh is explicit and the older context is retained only as a
        degraded fallback; it is never silently presented as fresh.
        """
        service = state.get("service_name") or "unknown"
        baseline_degraded = False
        try:
            since = datetime.now(timezone.utc) - timedelta(
                seconds=settings.AGENT_REFRESH_EVIDENCE_WINDOW_SECONDS
            )
            fresh_before = await self.evidence_collector.collect(service, since)
            state["before_context"] = {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "capture_reason": "immediately_before_execution",
                "live_evidence": fresh_before,
            }
            state.setdefault("context", {})["pre_execution_evidence"] = fresh_before
            self._audit(
                "pre_execution_evidence_refreshed",
                state,
                evidence_count=len(fresh_before.get("evidence", [])),
            )
        except Exception as exc:
            baseline_degraded = True
            logger.warning("Pre-execution evidence refresh failed: %s", exc)
            state.setdefault("context", {})["verification_precondition_degraded"] = True
            self._audit("pre_execution_evidence_refresh_failed", state, error=str(exc))

        result_state = await super()._execution_node(state)
        execution_result = result_state.get("execution_result") or {}
        execution_result["verification_baseline_degraded"] = baseline_degraded
        result_state["execution_result"] = execution_result
        if not execution_result.get("success"):
            result_state["terminal_reason"] = execution_result.get("reason") or "execution_failed"
        return result_state

    async def _memory_node(self, state: E2EState) -> E2EState:
        execution = state.get("execution_result") or {}
        if execution and not execution.get("success"):
            state["current_node"] = "memory"
            self._audit(
                "memory_writeback",
                state,
                persisted=False,
                verification_status=(state.get("verification_result") or {}).get("status"),
                reason="execution_not_successful",
            )
            return state
        return await super()._memory_node(state)
