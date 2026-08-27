"""RBAC کوچک و صریح Control Plane.

Roleها به‌جای اینکه داخل routeها hard-code شوند، به permissionهای granular نگاشت می‌شوند.
این تفکیک مهم است چون خواندن Incident، approve کردن high-risk و execute کردن action
سطوح اختیار متفاوتی دارند.
"""

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True, slots=True)
class RolePolicy:
    """یک role immutable و مجموعه permissionهای مجاز آن."""

    role: str
    permissions: FrozenSet[str]


# viewer فقط مشاهده می‌کند. operator کار روزمره و low-risk را انجام می‌دهد اما برای
# high-risk approval یا اجرای action approved اختیار ندارد. sre boundary حساس‌تر را دارد.
POLICIES = {
    "viewer": RolePolicy("viewer", frozenset({"read:incident", "read:audit"})),
    "operator": RolePolicy("operator", frozenset({"read:incident", "read:audit", "ingest:signal", "approve:low_risk", "execute:low_risk", "runbook:dry_run"})),
    "sre": RolePolicy("sre", frozenset({"read:incident", "read:audit", "ingest:signal", "approve:low_risk", "approve:high_risk", "execute:low_risk", "execute:approved", "runbook:dry_run"})),
}


def allowed(role: str, permission: str) -> bool:
    """بدون fallback یا wildcard بررسی می‌کند که role دقیقاً permission خواسته‌شده را دارد."""
    policy = POLICIES.get(role)
    return bool(policy and permission in policy.permissions)
