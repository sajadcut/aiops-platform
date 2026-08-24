from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class EvaluationThresholds:
    minimum_confidence: float = 0.70
    minimum_evidence: int = 1
    max_missing_fields: int = 0

DEFAULT_THRESHOLDS = EvaluationThresholds()
