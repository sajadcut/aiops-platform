"""Signed, short-lived config execution claims. Never expose the signing secret.

The control plane must hold AIOPS_CONFIG_APPLY_SIGNING_SECRET independently
of the MCP bearer token. VM-edge verifies the exact approval-bound intent.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import time


def _key() -> bytes:
    secret = os.environ.get("AIOPS_CONFIG_APPLY_SIGNING_SECRET", "")
    if len(secret) < 32 or secret.lower() in {"changeme", "change-me"}:
        raise PermissionError("config_signing_key_not_configured")
    return secret.encode("utf-8")



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
                 proposed_change: str) -> tuple[dict, str]:
    claims = {
        "version": 1,
        "approval_id": approval_id, "incident_id": incident_id,
        "target": target, "service": service, "config_file": config_file,
        "original_sha256": original_sha256, "candidate_sha256": candidate_sha256,
        "proposed_change": proposed_change, "expires": int(time.time()) + 55,
    }
    return claims, hmac.new(_key(), _message(claims), hashlib.sha256).hexdigest()


def verify_claim(claims: dict, signature: str, *, target: str, service: str) -> None:
    if not isinstance(claims, dict) or not isinstance(signature, str):
        raise PermissionError("config_execution_claim_missing")
    if set(claims) != {
        "version", "approval_id", "incident_id", "target", "service",
        "config_file", "original_sha256", "candidate_sha256",
        "proposed_change", "expires",
    }:
        raise PermissionError("config_execution_claim_fields")
    if claims.get("version") != 1 or claims.get("target") != target or claims.get("service") != service:
        raise PermissionError("config_execution_claim_scope")
    expiry = claims.get("expires")
    if type(expiry) is not int or not int(time.time()) <= expiry <= int(time.time()) + 60:
        raise PermissionError("config_execution_claim_expired")
    if not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise PermissionError("config_execution_claim_signature_invalid")
    signed = hmac.new(_key(), _message(claims), hashlib.sha256).hexdigest()
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
        "v1", "apply", str(claims["service"]).removesuffix(".service"),
        claims["config_file"], claims["original_sha256"],
        claims["candidate_sha256"], claims["approval_id"], claims["incident_id"],
        claims["target"], str(claims["expires"]),
    )
    if any("|" in str(v) or "\n" in str(v) for v in values):
        raise PermissionError("config_guard_claim_field_invalid")
    signature = private.sign("|".join(values).encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")
