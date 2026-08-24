from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class MemoryNamespace:
    name: str = "operational"
    source: str = "incident"
    allow_reuse_for_decision: bool = False

OPERATIONAL_MEMORY = MemoryNamespace()
