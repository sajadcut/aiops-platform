from __future__ import annotations

from typing import Any, Dict

import httpx
import jwt
from jwt import PyJWKClient

from apps.security.oidc import Identity


class OIDCTokenValidator:
    """Validate signed JWTs using configured OIDC issuer/audience/JWKS."""

    def __init__(self, issuer: str, audience: str, jwks_url: str):
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self._keys = PyJWKClient(jwks_url)

    def validate(self, token: str) -> Identity:
        signing_key = self._keys.get_signing_key_from_jwt(token).key
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
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()
