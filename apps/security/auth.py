from __future__ import annotations

from fastapi import Header, HTTPException

from domain.contracts.config import settings
from apps.security.rbac import allowed


def require_permission(required_permission: str):
    """Dependency enforcing the internal API key and RBAC permission."""
    async def dependency(
        x_api_key: str | None = Header(default=None),
        x_role: str | None = Header(default=None),
    ):
        expected = getattr(settings, "INTERNAL_API_KEY", "")
        if expected and x_api_key != expected:
            raise HTTPException(status_code=401, detail="invalid_api_key")
        role = x_role or "anonymous"
        if not allowed(role, required_permission):
            raise HTTPException(status_code=403, detail="insufficient_role")
        return {"role": role}

    return dependency
