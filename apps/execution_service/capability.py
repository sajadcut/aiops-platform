from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional
from uuid import uuid4

from domain.contracts.config import settings


class ExecutionCapabilityError(ValueError):
    pass


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def parameters_digest(parameters: Dict[str, Any]) -> str:
    encoded = json.dumps(parameters or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _secret() -> bytes:
    value = str(settings.EXECUTION_CAPABILITY_SECRET or "")
    if not value:
        raise ExecutionCapabilityError("execution_capability_secret_not_configured")
    if settings.APP_ENV == "production" and len(value.encode("utf-8")) < 32:
        raise ExecutionCapabilityError("execution_capability_secret_too_short")
    return value.encode("utf-8")


def issue_execution_capability(
    *,
    incident_id: str,
    approval_id: str,
    tool_name: str,
    action: str,
    target: str,
    parameters: Dict[str, Any],
    timeout: int,
    runbook_id: Optional[str] = None,
    runbook_version: Optional[str] = None,
    rollback: bool = False,
    execution_id: Optional[str] = None,
) -> str:
    now = int(time.time())
    ttl = int(settings.EXECUTION_CAPABILITY_TTL_SECONDS)
    if ttl <= 0:
        raise ExecutionCapabilityError("execution_capability_ttl_invalid")
    payload = {
        "v": 1,
        "iss": "aiops-control-plane",
        "env": settings.APP_ENV,
        "incident_id": str(incident_id),
        "approval_id": str(approval_id),
        "execution_id": str(execution_id or uuid4()),
        "tool_name": str(tool_name),
        "action": str(action),
        "target": str(target),
        "parameters_sha256": parameters_digest(parameters or {}),
        "timeout": int(timeout),
        "runbook_id": runbook_id,
        "runbook_version": runbook_version,
        "rollback": bool(rollback),
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid4()),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    body = _b64encode(raw)
    signature = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64encode(signature)}"


def verify_execution_capability(
    token: str,
    *,
    incident_id: Optional[str] = None,
    approval_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    action: Optional[str] = None,
    target: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    timeout: Optional[int] = None,
    runbook_id: Optional[str] = None,
    runbook_version: Optional[str] = None,
    rollback: Optional[bool] = None,
) -> Dict[str, Any]:
    try:
        body, supplied_signature = str(token).split(".", 1)
        expected_signature = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64decode(supplied_signature), expected_signature):
            raise ExecutionCapabilityError("execution_capability_signature_invalid")
        payload = json.loads(_b64decode(body).decode("utf-8"))
    except ExecutionCapabilityError:
        raise
    except Exception as exc:
        raise ExecutionCapabilityError("execution_capability_malformed") from exc

    now = int(time.time())
    if payload.get("iss") != "aiops-control-plane" or int(payload.get("v", 0)) != 1:
        raise ExecutionCapabilityError("execution_capability_issuer_invalid")
    if payload.get("env") != settings.APP_ENV:
        raise ExecutionCapabilityError("execution_capability_environment_mismatch")
    if int(payload.get("exp", 0)) <= now:
        raise ExecutionCapabilityError("execution_capability_expired")
    if int(payload.get("iat", 0)) > now + 30:
        raise ExecutionCapabilityError("execution_capability_iat_invalid")
    if not str(payload.get("jti") or ""):
        raise ExecutionCapabilityError("execution_capability_jti_missing")

    expected = {
        "incident_id": incident_id,
        "approval_id": approval_id,
        "tool_name": tool_name,
        "action": action,
        "target": target,
        "timeout": int(timeout) if timeout is not None else None,
        "runbook_id": runbook_id,
        "runbook_version": runbook_version,
        "rollback": bool(rollback) if rollback is not None else None,
    }
    for key, value in expected.items():
        if value is not None and payload.get(key) != value:
            raise ExecutionCapabilityError(f"execution_capability_{key}_mismatch")
    if parameters is not None and payload.get("parameters_sha256") != parameters_digest(parameters):
        raise ExecutionCapabilityError("execution_capability_parameters_mismatch")
    return payload
