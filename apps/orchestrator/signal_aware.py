from __future__ import annotations

from typing import Any, Dict

from apps.context_service.asset_identity import AssetIdentityResolver
from apps.orchestrator.e2e_graph import E2EOrchestrator, E2EState


class SignalAwareE2EOrchestrator(E2EOrchestrator):
    """E2E workflow variant that preserves the initiating signal as live Evidence.

    The normal E2E graph still owns reasoning, routing, RCA, evaluation,
    decision, execution, verification and memory. This subclass only merges the
    initiating signal with corroborating live Evidence gathered by the canonical
    Context node.
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
