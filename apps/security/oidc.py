from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Identity:
    subject: str
    roles: tuple[str, ...]
    email: Optional[str] = None


class OIDCIdentityAdapter:
    """Provider-neutral OIDC identity contract.

    Production deployments should populate Identity from a validated OIDC/JWT
    issuer. The adapter intentionally contains no vendor SDK dependency.
    """

    def __init__(self, issuer: str, audience: str):
        self.issuer = issuer
        self.audience = audience

    def validate_claims(self, claims: Dict[str, Any]) -> Identity:
        if claims.get("iss") != self.issuer:
            raise ValueError("invalid_issuer")
        aud = claims.get("aud")
        if aud != self.audience and self.audience not in (aud or []):
            raise ValueError("invalid_audience")
        subject = claims.get("sub")
        if not subject:
            raise ValueError("missing_subject")
        roles = claims.get("roles") or claims.get("groups") or []
        return Identity(subject=str(subject), roles=tuple(str(r) for r in roles), email=claims.get("email"))
