from dataclasses import dataclass, field
from typing import List

@dataclass(slots=True)
class Hypothesis:
    cause: str
    supporting_evidence: List[str] = field(default_factory=list)
    conflicting_evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def is_decision_ready(self, minimum: float = 0.70) -> bool:
        return self.confidence >= minimum and bool(self.supporting_evidence)
