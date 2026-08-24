from __future__ import annotations

from fastapi import Header, HTTPException

from domain.contracts.config import settings
from apps.security.rbac import is_allowed


def require_role(required_role: str):
    """Return a dependency that enforces a simple internal API role contract."""
    async def dependency(
        x_api_key: str | None = Header(default=None),
        x_role: str | None = Header(default=None),
    ):
        expected = getattr(settings, "INTERNAL_API_KEY", "")
        if expected and x_api_key != expected:
            raise HTTPException(status_code=401, detail="invalid_api_key")
        if not is_allowed(x_role or "anonymous", required_role):
            raise HTTPException(status_code=403, detail="insufficient_role")
        return {"role": x_role or "anonymous"}

    return dependency
