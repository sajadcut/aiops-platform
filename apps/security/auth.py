"""مرز احراز هویت و مجوزدهی API.

این ماژول فقط هویت را از OIDC/JWT یا Internal API Key می‌سازد و سپس RBAC را
اعمال می‌کند. هیچ route نباید صرف داشتن API key را معادل مجوز همه عملیات بداند؛
permission موردنیاز هر endpoint باید صریحاً با ``require_permission`` اعلام شود.
"""

from __future__ import annotations

from fastapi import Header, HTTPException

from apps.security.oidc import Identity
from apps.security.rbac import POLICIES, allowed
from apps.security.token_validator import OIDCTokenValidator
from domain.contracts.config import settings


def _identity_from_api_key(x_api_key: str | None) -> Identity | None:
    """Internal API key را به یک Identity با role محدودشده در `.env` تبدیل می‌کند."""
    expected = settings.INTERNAL_API_KEY or ""
    if not expected or x_api_key != expected:
        return None

    # خود secret فقط authentication را ثابت می‌کند؛ قدرت کاربر از role جداگانه
    # می‌آید تا یک API key داخلی ناخواسته به super-user تبدیل نشود.
    role = settings.INTERNAL_API_ROLE.strip().lower()
    if role not in POLICIES:
        raise RuntimeError(f"invalid_internal_api_role:{role}")
    return Identity(subject="api-key", roles=(role,))


def require_permission(required_permission: str):
    """OIDC/API-key را authenticate و سپس permission مشخص endpoint را enforce می‌کند."""

    async def dependency(
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
    ):
        identity: Identity | None = None
        oidc_ready = all((settings.OIDC_ISSUER_URL, settings.OIDC_AUDIENCE, settings.OIDC_JWKS_URL))

        # وقتی OIDC کامل پیکربندی شده، Bearer token باید واقعاً issuer/audience/signature
        # validation را پاس کند؛ خطای validator به authentication failure تبدیل می‌شود.
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

        # Authentication و Authorization دو مرحله جدا هستند. این check آخر اجازه
        # می‌دهد مثلاً operator incident را بخواند ولی approval پرریسک را انجام ندهد.
        if not any(allowed(role, required_permission) for role in identity.roles):
            raise HTTPException(status_code=403, detail="insufficient_role")
        return identity

    return dependency
