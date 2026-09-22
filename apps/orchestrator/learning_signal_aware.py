from __future__ import annotations

from apps.orchestrator.e2e_graph import E2EOrchestrator, E2EState
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator


class LearningSignalAwareE2EOrchestrator(SignalAwareE2EOrchestrator):
    """Signal-aware workflow with positive and negative Operational Memory write-back."""

    async def _memory_node(self, state: E2EState) -> E2EState:
        return await E2EOrchestrator._memory_node(self, state)
