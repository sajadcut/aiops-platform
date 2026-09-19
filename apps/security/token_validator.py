from __future__ import annotations

import time
from typing import Any, Dict

import httpx
from integrations.http_transport import insecure_async_client, insecure_ssl_context
import jwt
from jwt import PyJWKClient

from apps.security.oidc import Identity
from domain.contracts.logging import logger


class OIDCTokenValidator:
    """Validate signed JWTs using configured OIDC issuer/audience/JWKS."""

    def __init__(self, issuer: str, audience: str, jwks_url: str):
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self._keys = PyJWKClient(jwks_url, ssl_context=insecure_ssl_context())

    def validate(self, token: str) -> Identity:
        started = time.perf_counter()
        try:
            signing_key = self._keys.get_signing_key_from_jwt(token).key
        except Exception as exc:
            logger.warning(
                "oidc_jwks_key_lookup_failed",
                component="oidc_jwks",
                error_type=type(exc).__name__,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            raise
        logger.info(
            "oidc_jwks_key_lookup_completed",
            component="oidc_jwks",
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        claims: Dict[str, Any] = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=self.audience,
            issuer=self.issuer,
            options={"require": ["sub", "iss", "aud"]},
        )
        roles = claims.get("roles") or claims.get("groups") or []
        return Identity(
            subject=str(claims["sub"]),
            roles=tuple(str(role) for role in roles),
            email=claims.get("email"),
        )


async def discover_jwks(url: str) -> Dict[str, Any]:
    async with insecure_async_client(timeout=5.0, component="oidc_jwks") as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()
