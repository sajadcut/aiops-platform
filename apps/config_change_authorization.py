"""Signed, short-lived config execution claims derived from MCP_BEARER_TOKEN.

A versioned, purpose-specific HMAC subkey avoids directly using the transport
bearer token as the signing key. The transport token remains a shared trust
root: whoever knows it can derive this subkey. Approval consumption, bounded
claims, VM target binding, source hash and replay defenses must remain active.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import time


_SIGNING_CONTEXT = b"aiops/configuration-apply/approval-claim/v1"
_CANDIDATE_ENCRYPTION_CONTEXT = b"aiops/configuration-candidate/aes-256-gcm/v1"


def _derive_mcp_key(context: bytes, *, target: str | None = None) -> bytes:
    """Derive a domain-separated 32-byte key from the existing MCP bearer.

    Context is intentionally chosen by trusted code, never a model or caller.
    This retains the existing MCP token strength policy and env precedence.
    """
    if context not in {_SIGNING_CONTEXT, _CANDIDATE_ENCRYPTION_CONTEXT}:
        raise PermissionError("mcp_key_purpose_not_registered")
    from domain.contracts.config import settings
    # Deployed settings read environment and .env. An explicit runtime env
    # override is useful in isolated tests and takes precedence over settings.
    if settings.MCP_SERVER_PROVIDER == "vm_agent":
        # An installed agent never needs the fleet-wide Control Plane secret.
        token = settings.VM_AGENT_BEARER_TOKEN or ""
    elif settings.VM_EXECUTION_BACKEND == "agent" and context == _SIGNING_CONTEXT and target:
        # The API signs for exactly the agent named in the approved intent.
        token = settings.VM_AGENT_TOKENS.get(target) or ""
    else:
        token = (os.environ["MCP_BEARER_TOKEN"] if "MCP_BEARER_TOKEN" in os.environ
                 else settings.MCP_BEARER_TOKEN or "")
    if not isinstance(token, str) or not token:
        raise PermissionError("mcp_bearer_token_not_configured_for_signing")
    if (len(token.encode("utf-8")) < 32
            or token.lower().strip() in {"changeme", "change-me", "test", "secret"}):
        raise PermissionError("mcp_bearer_token_too_weak_for_signing")
    # No bearer bytes appear in claims, logs, headers beyond original MCP auth,
    # or incident metadata; HMAC output serves only as an internal subkey.
    return hmac.new(token.encode("utf-8"), context, hashlib.sha256).digest()


def _key(*, target: str | None = None) -> bytes:
    """Approval HMAC signing key: stable and isolated from candidate encryption."""
    return _derive_mcp_key(_SIGNING_CONTEXT, target=target)


def candidate_encryption_key() -> bytes:
    """AES-256-GCM subkey for the VM MCP candidate vault; no new configuration."""
    return _derive_mcp_key(_CANDIDATE_ENCRYPTION_CONTEXT)



def config_signing_ready() -> bool:
    """Local readiness only. Never expose key bytes or report VM MCP readiness."""
    try:
        _key()
    except PermissionError:
        return False
    return True


def _message(claims: dict) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def create_claim(*, approval_id: str, incident_id: str, target: str, service: str,
                 config_file: str, original_sha256: str, candidate_sha256: str,
                 proposed_change: str,
                 start_service_after_apply: bool = False) -> tuple[dict, str]:
    claims = {
        "version": 1,
        "approval_id": approval_id, "incident_id": incident_id,
        "target": target, "service": service, "config_file": config_file,
        "original_sha256": original_sha256, "candidate_sha256": candidate_sha256,
        "proposed_change": proposed_change, "expires": int(time.time()) + 55,
    }
    if type(start_service_after_apply) is not bool:
        raise PermissionError("config_recovery_scope_invalid")
    if start_service_after_apply:
        claims["recovery_action"] = "start_service"
    return claims, hmac.new(_key(target=target), _message(claims), hashlib.sha256).hexdigest()


def verify_claim(claims: dict, signature: str, *, target: str, service: str) -> None:
    if not isinstance(claims, dict) or not isinstance(signature, str):
        raise PermissionError("config_execution_claim_missing")
    required = {
        "version", "approval_id", "incident_id", "target", "service",
        "config_file", "original_sha256", "candidate_sha256",
        "proposed_change", "expires",
    }
    if set(claims) not in (required, required | {"recovery_action"}):
        raise PermissionError("config_execution_claim_fields")
    if "recovery_action" in claims and claims["recovery_action"] != "start_service":
        raise PermissionError("config_execution_claim_recovery_scope")
    if claims.get("version") != 1 or claims.get("target") != target or claims.get("service") != service:
        raise PermissionError("config_execution_claim_scope")
    expiry = claims.get("expires")
    if type(expiry) is not int or not int(time.time()) <= expiry <= int(time.time()) + 60:
        raise PermissionError("config_execution_claim_expired")
    if not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise PermissionError("config_execution_claim_signature_invalid")
    signed = hmac.new(_key(target=target), _message(claims), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signed, signature):
        raise PermissionError("config_execution_claim_signature_invalid")


def sign_root_guard(claims: dict) -> str:
    """Ed25519 root guard signature; VM stores only its verification public key.

    Ed25519 private seed is securely injected into the VM MCP worker only;
    no private key ever appears in SSH argv, stdout or the target VM.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    encoded = os.environ.get("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY", "")
    try:
        seed = base64.b64decode(encoded, validate=True)
        if len(seed) != 32:
            raise ValueError("wrong_key_size")
        private = Ed25519PrivateKey.from_private_bytes(seed)
    except (ValueError, TypeError) as exc:
        raise PermissionError("config_guard_private_key_missing") from exc
    values = (
        "v1", "apply", str(claims["service"]).lower().removesuffix(".service"),
        claims["config_file"], claims["original_sha256"],
        claims["candidate_sha256"], claims["approval_id"], claims["incident_id"],
        claims["target"], str(claims["expires"]),
    )
    if any("|" in str(v) or "\n" in str(v) for v in values):
        raise PermissionError("config_guard_claim_field_invalid")
    signature = private.sign("|".join(values).encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")
