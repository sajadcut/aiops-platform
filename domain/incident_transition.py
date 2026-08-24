from typing import Set

TRANSITIONS = {
    "open": {"analyzing", "escalated"},
    "analyzing": {"resolved", "escalated"},
    "resolved": {"closed", "analyzing"},
    "escalated": {"analyzing", "closed"},
    "closed": set(),
}

def can_transition(current: str, target: str) -> bool:
    return target in TRANSITIONS.get(current, set())
