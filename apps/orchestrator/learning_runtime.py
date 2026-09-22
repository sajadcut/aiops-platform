from __future__ import annotations

from apps.orchestrator.runtime import DurableWorkflowRuntime


class LearningDurableWorkflowRuntime(DurableWorkflowRuntime):
    """Backward-compatible alias for the canonical durable Memory-v2 runtime.

    Outcome learning, including failed/blocked write-back, is implemented in
    DurableWorkflowRuntime and SignalAwareE2EOrchestrator. Existing imports may
    keep using this class without creating a second execution semantics.
    """

    pass
