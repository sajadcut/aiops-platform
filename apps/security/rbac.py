from dataclasses import dataclass
from typing import FrozenSet

@dataclass(frozen=True, slots=True)
class RolePolicy:
    role: str
    permissions: FrozenSet[str]

POLICIES = {
    "viewer": RolePolicy("viewer", frozenset({"read:incident", "read:audit"})),
    "operator": RolePolicy("operator", frozenset({"read:incident", "read:audit", "approve:low_risk"})),
    "sre": RolePolicy("sre", frozenset({"read:incident", "read:audit", "approve:low_risk", "approve:high_risk"})),
}

def allowed(role: str, permission: str) -> bool:
    policy = POLICIES.get(role)
    return bool(policy and permission in policy.permissions)
