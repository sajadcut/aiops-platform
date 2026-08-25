from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True, slots=True)
class RolePolicy:
    role: str
    permissions: FrozenSet[str]


POLICIES = {
    "viewer": RolePolicy("viewer", frozenset({"read:incident", "read:audit"})),
    "operator": RolePolicy("operator", frozenset({"read:incident", "read:audit", "ingest:signal", "approve:low_risk", "execute:low_risk", "runbook:dry_run"})),
    "sre": RolePolicy("sre", frozenset({"read:incident", "read:audit", "ingest:signal", "approve:low_risk", "approve:high_risk", "execute:low_risk", "execute:approved", "runbook:dry_run"})),
}


def allowed(role: str, permission: str) -> bool:
    policy = POLICIES.get(role)
    return bool(policy and permission in policy.permissions)
