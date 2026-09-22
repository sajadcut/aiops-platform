from __future__ import annotations

from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator


class LearningSignalAwareE2EOrchestrator(SignalAwareE2EOrchestrator):
    """Backward-compatible alias for the canonical Memory-v2 signal workflow.

    Positive and negative Operational Memory write-back now lives directly in
    SignalAwareE2EOrchestrator/E2EOrchestrator, so this class intentionally adds
    no behavioral override.
    """

    pass
