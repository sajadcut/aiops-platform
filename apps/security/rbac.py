from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True, slots=True)
class RolePolicy:
    role: str
    permissions: FrozenSet[str]


COMMON_READ = frozenset({"read:incident", "read:audit"})

POLICIES = {
    "viewer": RolePolicy("viewer", COMMON_READ),
    "operator": RolePolicy(
        "operator",
        COMMON_READ
        | frozenset({"approve:low_risk", "execute:low_risk", "runbook:dry_run", "manage:knowledge"}),
    ),
    "sre": RolePolicy(
        "sre",
        COMMON_READ
        | frozenset({
            "approve:low_risk",
            "approve:high_risk",
            "execute:low_risk",
            "execute:approved",
            "runbook:dry_run",
            "manage:knowledge",
        }),
    ),
}


def allowed(role: str, permission: str) -> bool:
    policy = POLICIES.get(role)
    return bool(policy and permission in policy.permissions)