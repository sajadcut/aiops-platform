from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from agents.shared.base import UNTRUSTED_INPUT_POLICY
from agents.shared.domain_agent import DomainDiagnosticAgent
from agents.shared.telemetry import AgentTelemetry
from apps.context_service.asset_identity import AssetIdentityResolver
from apps.context_service.knowledge_topology import KnowledgeTopologyResolver
from apps.decision_engine import DecisionEngine
from apps.execution_service.tools.registry import tool_registry
from apps.orchestrator.e2e_graph import E2EOrchestrator, E2EState
from apps.remediation_planner import RemediationPlanner
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
        service_hint = state.get("service_name") or context.get("service")

        # Source notifications can arrive after the causal telemetry interval.
        # Anchor an extra read-only evidence collection window to the original
        # trigger timestamp instead of relying only on a "now" window.
        history_key = None
        lookback_seconds = 0
        lookahead_seconds = 0
        if isinstance(trigger_signal, dict) and isinstance(trigger_signal.get("raw_data"), dict):
            source = str(trigger_signal.get("source") or "").lower()
            raw_trigger = trigger_signal["raw_data"]
            if source == "elasticsearch" and raw_trigger.get("elastic_alert_kind") == "ml_anomaly":
                history_key = "elastic_anomaly_evidence_window"
                lookback_seconds = settings.ELASTIC_ANOMALY_CONTEXT_LOOKBACK_SECONDS
                lookahead_seconds = settings.ELASTIC_ANOMALY_CONTEXT_LOOKAHEAD_SECONDS
            elif source == "prometheus" and raw_trigger.get("prometheus_alert_kind") == "alertmanager":
                history_key = "prometheus_alert_evidence_window"
                lookback_seconds = settings.PROMETHEUS_ALERT_CONTEXT_LOOKBACK_SECONDS
                lookahead_seconds = settings.PROMETHEUS_ALERT_CONTEXT_LOOKAHEAD_SECONDS

        if history_key:
            try:
                raw_timestamp = str(trigger_signal.get("timestamp") or "").strip()
                trigger_time = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
                if trigger_time.tzinfo is None:
                    trigger_time = trigger_time.replace(tzinfo=timezone.utc)
                trigger_time = trigger_time.astimezone(timezone.utc)
                window_start = trigger_time - timedelta(seconds=lookback_seconds)
                window_end = trigger_time + timedelta(seconds=lookahead_seconds)
                now = datetime.now(timezone.utc)
                if window_end > now:
                    window_end = now
                if window_end < window_start:
                    window_end = trigger_time
                historical = await self.evidence_collector.collect(
                    str(service_hint or "unknown"),
                    window_start,
                    window_end,
                )
                historical_items = [
                    item for item in historical.get("evidence", [])
                    if isinstance(item, dict)
                ]
                collected.extend(historical_items)
                context[history_key] = {
                    "anchor": trigger_time.isoformat(),
                    "since": window_start.isoformat(),
                    "until": window_end.isoformat(),
                    "evidence_count": len(historical_items),
                    "policy": "trigger_time_anchored_read_only_enrichment",
                }
            except Exception as exc:
                logger.warning(
                    "source_trigger_context_window_failed",
                    source=str((trigger_signal or {}).get("source") or "unknown"),
                    error_type=type(exc).__name__,
                )
                context[history_key] = {
                    "status": "error",
                    "error_type": type(exc).__name__,
                }

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
        live_asset_context = AssetIdentityResolver.resolve(merged_evidence, service_hint)

        discovery_knowledge = [
            item for item in initial_context.get("knowledge_results", [])
            if isinstance(item, dict)
        ]
        analysis_knowledge = [
            item for item in context.get("knowledge_results", [])
            if isinstance(item, dict)
        ]
        knowledge_by_id: Dict[str, Dict[str, Any]] = {}
        for item in discovery_knowledge + analysis_knowledge:
            key = str(item.get("source_id") or item.get("id") or len(knowledge_by_id))
            knowledge_by_id[key] = item

        trigger_text = ""
        if isinstance(trigger_signal, dict):
            trigger_text = str(trigger_signal.get("summary") or "")
        expected_fqdns = KnowledgeTopologyResolver.extract_fqdns(
            f"{trigger_text} {state.get('evidence_summary') or ''}"
        )
        knowledge_topology = KnowledgeTopologyResolver.resolve(
            knowledge_by_id.values(),
            expected_fqdns=expected_fqdns,
        )
        topology_context = KnowledgeTopologyResolver.reconcile(
            live_asset_context,
            knowledge_topology,
        )
        asset_context = dict(topology_context.get("effective_asset") or live_asset_context)

        resolved_service = asset_context.get("service") or service_hint
        if resolved_service:
            state["service_name"] = str(resolved_service)
            context["service"] = str(resolved_service)

        live = dict(state.get("live_evidence") or {})
        live["evidence"] = merged_evidence
        live["asset_context"] = asset_context
        live["live_asset_context"] = live_asset_context
        live["knowledge_topology"] = knowledge_topology
        live["topology_context"] = topology_context
        context["evidence"] = merged_evidence
        context["live_evidence"] = live
        context["asset_context"] = asset_context
        context["live_asset_context"] = live_asset_context
        context["topology_context"] = topology_context
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
            knowledge_assisted=bool(asset_context.get("knowledge_assisted")),
            topology_conflict_count=len(topology_context.get("conflicts") or []),
            requires_live_verification=bool(topology_context.get("requires_live_verification")),
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
        phase_started = time.perf_counter()
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
            duration_ms=round((time.perf_counter() - phase_started) * 1000, 3),
        )
        return state

    @staticmethod
    def _deterministic_rca_fallback(state: E2EState) -> str:
        for finding in state.get("analysis_results", []) or []:
            if not isinstance(finding, dict):
                continue
            details = finding.get("analysis_details") or {}
            if isinstance(details, dict) and details.get("deterministic_fault") == "service_stopped":
                service = str(state.get("service_name") or "service")
                return (
                    f"Live Evidence confirms {service} is stopped while configuration validation is acceptable. "
                    "Use the governed start_service recovery path only after Decision/Approval, refresh execution "
                    "preconditions immediately before the write, and verify service state plus the original listener/TCP symptom afterward. "
                    "Historical root cause remains under investigation and is not required to authorize the current-state recovery proposal."
                )
        return "Manual investigation required: RCA generation failed."

    def _rca_auxiliary_context(self, state: E2EState) -> Dict[str, Any]:
        """Expose bounded governed auxiliary context to RCA without bypassing attribution."""
        inp = self._agent_input(state)
        cited_memory_ids = {
            str(memory_id)
            for finding in state.get("findings", []) or []
            if isinstance(finding, dict)
            for memory_id in finding.get("historical_memory_ids", []) or []
            if str(memory_id).strip()
        }
        projected_memory = [
            item
            for item in DomainDiagnosticAgent.memory_items(inp)
            if str(item.get("id") or "") in cited_memory_ids
        ]
        knowledge = DomainDiagnosticAgent.knowledge_items(inp)
        return {
            "knowledge": DomainDiagnosticAgent._bounded_prompt_value(knowledge),
            "knowledge_status": DomainDiagnosticAgent._bounded_prompt_value(
                (state.get("context") or {}).get("knowledge_status", {})
            ),
            "cited_historical_memory": DomainDiagnosticAgent._bounded_prompt_value(
                projected_memory
            ),
            "cited_memory_ids": sorted(cited_memory_ids),
            "policy": (
                "auxiliary_only_not_live_evidence; historical memory shown here "
                "was already cited by an analysis agent; it cannot authorize an "
                "action and every operational claim must be revalidated from live evidence"
            ),
        }

    async def _rca_node(self, state: E2EState) -> E2EState:
        """Bound RCA context so provider token limits cannot erase deterministic recovery."""
        phase_started = time.perf_counter()
        state["current_node"] = "rca"
        raw_evidence = state.get("context", {}).get("evidence", [])
        compact_evidence = DomainDiagnosticAgent._prompt_evidence(
            raw_evidence if isinstance(raw_evidence, list) else []
        )
        compact_findings = DomainDiagnosticAgent._bounded_prompt_value(
            list(state.get("analysis_results", []) or [])[: settings.AGENT_MAX_PARALLELISM]
        )
        compact_coordination = DomainDiagnosticAgent._bounded_prompt_value(
            state.get("coordination", {})
        )
        compact_triage = DomainDiagnosticAgent._bounded_prompt_value(
            state.get("triage_result", {})
        )
        auxiliary = self._rca_auxiliary_context(state)
        prompt = (
            f"{UNTRUSTED_INPUT_POLICY}\n\n"
            "You are the RCA synthesis stage. LIVE EVIDENCE is authoritative. "
            "Separate the currently proven operational state from uncertain historical root cause. "
            "Preserve meaningful disagreements and falsification checks, but do not let speculative historical-cause hypotheses override direct current-state telemetry. "
            "RAG/Memory are auxiliary. Only the historical Memory items already cited by analysis agents are supplied here. "
            "Never treat them as current Evidence, never use them to bypass current preconditions, and never infer action authorization from them. "
            "If auxiliary context conflicts with LIVE EVIDENCE, LIVE EVIDENCE wins. "
            "Never claim execution or approval. Return a concise assessment and action plan.\n"
            f"Triage={json.dumps(compact_triage, default=str)}\n"
            f"SpecialistFindings={json.dumps(compact_findings, default=str)}\n"
            f"Coordination={json.dumps(compact_coordination, default=str)}\n"
            f"AuxiliaryKnowledge={json.dumps(auxiliary.get('knowledge', []), default=str)}\n"
            f"KnowledgeStatus={json.dumps(auxiliary.get('knowledge_status', {}), default=str)}\n"
            f"CitedHistoricalMemory={json.dumps(auxiliary.get('cited_historical_memory', []), default=str)}\n"
            f"LiveEvidence={json.dumps(compact_evidence, default=str)}"
        )
        max_tokens = min(max(int(settings.AGENT_MAX_TOKENS) * 2, 1600), 4096)
        try:
            response = await asyncio.wait_for(
                self.llm.generate(
                    prompt,
                    temperature=settings.AGENT_LLM_TEMPERATURE,
                    max_tokens=max_tokens,
                ),
                timeout=settings.AGENT_TIMEOUT_SECONDS,
            )
            finish_reason = str(response.finish_reason or "").strip().lower()
            if finish_reason in {"length", "max_tokens"}:
                raise RuntimeError("rca_response_truncated")
            state["final_plan"] = response.content
        except Exception as exc:
            state["final_plan"] = self._deterministic_rca_fallback(state)
            logger.error("RCA generation failed: %s", exc)
        state["confidence"] = float(
            state.get("coordination", {}).get(
                "confidence", self._average_confidence(state.get("findings", []))
            )
        )
        self._audit(
            "rca_completed",
            state,
            confidence=state["confidence"],
            coordination=state.get("coordination", {}),
            prompt_evidence_count=len(compact_evidence),
            knowledge_context_count=len(auxiliary.get("knowledge", []) or []),
            cited_memory_context_count=len(
                auxiliary.get("cited_historical_memory", []) or []
            ),
            cited_memory_ids=auxiliary.get("cited_memory_ids", []),
            bounded_context=True,
            duration_ms=round((time.perf_counter() - phase_started) * 1000, 3),
        )
        return state

    async def _decision_node(self, state: E2EState) -> E2EState:
        """Bind deterministic policy to the concrete tool/action/target request."""
        state["current_node"] = "decision"
        request = dict(state.get("execution_request") or {})
        remediation_plan: Dict[str, Any] = dict(state.get("remediation_plan") or {})
        if not request:
            remediation_plan = RemediationPlanner.plan(state)
            state["remediation_plan"] = remediation_plan
            planned_request = remediation_plan.get("execution_request")
            if remediation_plan.get("status") == "planned" and isinstance(planned_request, dict):
                request = dict(planned_request)
                state["execution_request"] = request
                service = str(remediation_plan.get("service") or "").strip()
                if service:
                    state["service_name"] = service
                    state.setdefault("context", {})["service"] = service
                self._audit(
                    "remediation_plan_generated",
                    state,
                    runbook_id=remediation_plan.get("runbook_id"),
                    runbook_version=remediation_plan.get("runbook_version"),
                    tool=request.get("tool_name"),
                    action=request.get("action"),
                    target=request.get("target"),
                    service=service or None,
                    target_port=remediation_plan.get("target_port"),
                    evidence_refs=remediation_plan.get("evidence_refs", []),
                )
            else:
                self._audit(
                    "remediation_plan_not_generated",
                    state,
                    reason=remediation_plan.get("reason"),
                    evidence_refs=remediation_plan.get("evidence_refs", []),
                )

        tool = tool_registry.get_tool(str(request.get("tool_name") or "")) if request else None
        topology_context = dict((state.get("context") or {}).get("topology_context") or {})
        knowledge_identity_unverified = bool(topology_context.get("requires_live_verification"))
        planner_live_verified = bool(
            request
            and str(request.get("agent_name") or "") == "remediation_planner"
            and remediation_plan.get("live_identity_verified") is True
        )
        target_identity_verified = planner_live_verified or not bool(
            request
            and tool is not None
            and tool.requires_approval
            and knowledge_identity_unverified
        )
        result = DecisionEngine.evaluate_plan(
            state.get("final_plan", ""),
            state.get("findings", []),
            execution_request=request or None,
            tool_risk_level=tool.risk_level if tool is not None else None,
            tool_requires_approval=bool(tool.requires_approval) if tool is not None else False,
            tool_exists=(tool is not None) if request else True,
            target_identity_verified=target_identity_verified,
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
        """Refresh and revalidate live preconditions immediately before execution."""
        service = state.get("service_name") or "unknown"
        request = dict(state.get("execution_request") or {})
        planner_write = str(request.get("agent_name") or "") == "remediation_planner"
        baseline_degraded = False
        fresh_before: Dict[str, Any] = {}
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
            if planner_write:
                state["execution_result"] = {
                    "success": False,
                    "tool_name": request.get("tool_name"),
                    "action": request.get("action"),
                    "target": request.get("target"),
                    "execution_blocked": True,
                    "reason": "fresh_execution_precondition_unavailable",
                    "verification_baseline_degraded": True,
                }
                state["terminal_reason"] = "fresh_execution_precondition_unavailable"
                self._audit(
                    "remediation_execution_precondition_blocked",
                    state,
                    reason="fresh_execution_precondition_unavailable",
                )
                return state

        if planner_write:
            precondition = RemediationPlanner.revalidate_execution(
                request, fresh_before.get("evidence", [])
            )
            state["remediation_precondition"] = precondition
            if not precondition.get("safe_to_execute"):
                state["execution_result"] = {
                    "success": False,
                    "tool_name": request.get("tool_name"),
                    "action": request.get("action"),
                    "target": request.get("target"),
                    "execution_blocked": True,
                    "reason": str(precondition.get("reason") or "execution_precondition_failed"),
                    "verification_baseline_degraded": baseline_degraded,
                }
                state["terminal_reason"] = "execution_precondition_failed"
                self._audit(
                    "remediation_execution_precondition_blocked",
                    state,
                    reason=precondition.get("reason"),
                    evidence_refs=precondition.get("evidence_refs", []),
                )
                return state
            self._audit(
                "remediation_execution_precondition_verified",
                state,
                target=precondition.get("target"),
                service=precondition.get("service"),
                evidence_refs=precondition.get("evidence_refs", []),
            )

        result_state = await super()._execution_node(state)
        execution_result = result_state.get("execution_result") or {}
        execution_result["verification_baseline_degraded"] = baseline_degraded
        result_state["execution_result"] = execution_result
        if not execution_result.get("success"):
            result_state["terminal_reason"] = execution_result.get("reason") or "execution_failed"
        return result_state

    async def _memory_node(self, state: E2EState) -> E2EState:
        # Operational Memory v2 deliberately keeps both positive and negative
        # governed outcomes. Execution failure or policy blocking is historical
        # experience, not a reason to suppress write-back. Resolution semantics
        # remain unchanged: only successful independent verification resolves
        # the incident.
        return await super()._memory_node(state)
