"""Compatibility facade for the governed Agent orchestration graph.

The historical WorkflowOrchestrator implementation duplicated routing/RCA and
contained a direct Mock LLM fallback. All callers now receive the same smart
routing, evidence-first, collaborative, Evaluator-gated behavior implemented by
SignalAwareE2EOrchestrator.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from integrations.llm.base import LLMAdapter


class WorkflowOrchestrator:
    """Backward-compatible facade; not a second orchestration implementation."""

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None, db: Any = None):
        self._delegate = SignalAwareE2EOrchestrator(llm_adapter=llm_adapter, db=db)
        self.graph = self._delegate.graph

    async def run(self, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        return await self._delegate.run(initial_state)
