from __future__ import annotations

from fastapi import Header, HTTPException

from apps.security.oidc import Identity
from apps.security.rbac import allowed
from apps.security.token_validator import OIDCTokenValidator
from domain.contracts.config import settings


def _identity_from_api_key(x_api_key: str | None, x_role: str | None) -> Identity | None:
    expected = getattr(settings, "INTERNAL_API_KEY", "")
    if not expected or x_api_key != expected:
        return None
    role = x_role or "operator"
    return Identity(subject="api-key", roles=(role,))


def require_permission(required_permission: str):
    """Authenticate with OIDC Bearer JWT, or internal API key for controlled automation."""
    async def dependency(
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        x_role: str | None = Header(default=None),
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
            identity = _identity_from_api_key(x_api_key, x_role)

        if identity is None:
            raise HTTPException(status_code=401, detail="authentication_required")
        if not any(allowed(role, required_permission) for role in identity.roles):
            raise HTTPException(status_code=403, detail="insufficient_role")
        return identity

    return dependency
