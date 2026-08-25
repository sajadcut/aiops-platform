from __future__ import annotations

from typing import Any, Dict

from agents.shared.telemetry import AgentTelemetry
from apps.context_service.asset_identity import AssetIdentityResolver
from apps.orchestrator.e2e_graph import E2EOrchestrator, E2EState


class SignalAwareE2EOrchestrator(E2EOrchestrator):
    """Collaborative E2E workflow for source-triggered and API-triggered incidents.

    It preserves initiating Evidence and exposes structured peer findings,
    consensus, contradictions and evidence requests to subsequent specialist
    passes. Agents do not free-chat; collaboration happens through audited
    Incident state.
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
        context["peer_findings"] = findings
        context["agent_coordination"] = {
            "confidence": coordination.get("confidence"),
            "agreement_score": coordination.get("agreement_score"),
            "disagreement": coordination.get("disagreement"),
            "contradictions": coordination.get("contradictions", []),
            "consensus_hypotheses": coordination.get("consensus_hypotheses", []),
            "missing_evidence": coordination.get("missing_evidence", []),
            "evidence_requests": coordination.get("evidence_requests", []),
            "handoff_agents": coordination.get("handoff_agents", []),
        }

    async def _parallel_agents_node(self, state: E2EState) -> E2EState:
        state["current_node"] = "parallel_agents"
        routing = state.get("routing") or self.coordinator.select_agents(
            state.get("triage_result", {}), self.registry.enabled_names()
        )
        selected = list(routing.get("selected", []))

        # First specialist pass shares the same live Incident context.
        findings = await self._run_specialists(selected, state)
        coordination = self.coordinator.synthesize(findings)
        self._publish_peer_context(state, findings, coordination)

        # Structured handoff / second opinion. New Agents see prior peer findings
        # and the coordinator's consensus/contradictions in their AgentInput context.
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

        # Bounded targeted Evidence refresh. Re-running specialists after refresh
        # now includes the previous peer analysis, making the second reasoning pass
        # genuinely cumulative instead of stateless.
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
