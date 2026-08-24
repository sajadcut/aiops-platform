from dataclasses import dataclass
from typing import FrozenSet

@dataclass(frozen=True, slots=True)
class EvidenceSourcePolicy:
    allowed_sources: FrozenSet[str] = frozenset({"zabbix", "elasticsearch", "prometheus"})
    minimum_confidence: float = 0.50

    def allows(self, source: str, confidence: float = 1.0) -> bool:
        return source.lower() in self.allowed_sources and confidence >= self.minimum_confidence

DEFAULT_EVIDENCE_POLICY = EvidenceSourcePolicy()
