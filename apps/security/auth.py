"""API authentication and authorization boundary."""

from __future__ import annotations

from fastapi import Header, HTTPException, Request

from apps.security.oidc import Identity
from apps.security.rbac import POLICIES, allowed
from apps.security.token_validator import OIDCTokenValidator
from domain.contracts.config import settings


def _identity_from_api_key(x_api_key: str | None) -> Identity | None:
    expected = settings.INTERNAL_API_KEY or ""
    if not expected or x_api_key != expected:
        return None

    role = settings.INTERNAL_API_ROLE.strip().lower()
    if role not in POLICIES:
        raise RuntimeError(f"invalid_internal_api_role:{role}")
    return Identity(subject="api-key", roles=(role,))


def require_permission(required_permission: str):
    """Authenticate with OIDC/API-key, enforce RBAC, and bind identity to request context."""

    async def dependency(
        request: Request,
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
    ):
        identity: Identity | None = None
        oidc_ready = all((settings.OIDC_ISSUER_URL, settings.OIDC_AUDIENCE, settings.OIDC_JWKS_URL))

        if authorization and authorization.lower().startswith("bearer ") and oidc_ready:
            token = authorization.split(" ", 1)[1].strip()
            try:
                identity = OIDCTokenValidator(
                    settings.OIDC_ISSUER_URL,
                    settings.OIDC_AUDIENCE,
                    settings.OIDC_JWKS_URL,
                ).validate(token)
            except Exception as exc:
                raise HTTPException(status_code=401, detail="invalid_oidc_token") from exc
        else:
            identity = _identity_from_api_key(x_api_key)

        if identity is None:
            raise HTTPException(status_code=401, detail="authentication_required")

        if not any(allowed(role, required_permission) for role in identity.roles):
            raise HTTPException(status_code=403, detail="insufficient_role")

        request.state.identity_subject = identity.subject
        request.state.identity_roles = list(identity.roles)
        return identity

    return dependency
