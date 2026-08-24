from typing import Iterable


class ToolPolicy:
    """Deny-by-default policy gate for operational tools."""

    @staticmethod
    def validate(environment: str, risk_level: str, allowlisted: bool, requires_approval: bool, approved: bool) -> bool:
        if not allowlisted:
            return False
        if environment.lower() == "production" and risk_level.lower() in {"high", "critical"} and not approved:
            return False
        if requires_approval and not approved:
            return False
        return True
