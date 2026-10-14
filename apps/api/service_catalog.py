"""Human-reviewed service health catalog and bounded, read-only HTTP checks.

An SRE can configure *observability*, never execution authority. URLs/hosts from
chat, LLM, or unvalidated service metadata can never choose a probe target.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from uuid import UUID, uuid4
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text

from apps.api.incident_chat import _incident_status_scope
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from integrations.http_transport import verified_async_client
from domain.contracts.rate_limit import rate_limiter_strict

router = APIRouter()
_ALLOWED_HEALTH = re.compile(r"^/[A-Za-z0-9/_ .-]{0,90}$")
_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}$")


class ServiceHealthProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    platform: Literal["vm_systemd", "windows_service", "kubernetes"] = "vm_systemd"
    owner: str | None = Field(default=None, max_length=120)
    expected_port: int | None = Field(default=None, ge=1, le=65535)
    health_path: str | None = Field(default=None, max_length=92)
    health_scheme: Literal["http", "https"] = "http"
    dependencies: list[str] = Field(default_factory=list, max_length=15)
    restart_runbook_id: str | None = Field(default=None, max_length=100)
    verification_notes: str | None = Field(default=None, max_length=300)

    @field_validator("health_path")
    @classmethod
    def check_health_path(cls, v):
        if v is not None and (not _ALLOWED_HEALTH.fullmatch(v)
                               or "//" in v or ".." in v or " " in v):
            raise ValueError("health_path_must_be_safe_absolute_path")
        return v

    @field_validator("dependencies")
    @classmethod
    def check_dependencies(cls, v):
        if any(not _NAME.fullmatch(item) for item in v) or len(set(v)) != len(v):
            raise ValueError("invalid_dependency_name")
        return v

    @field_validator("owner", "restart_runbook_id", "verification_notes")
    @classmethod
    def no_control_chars(cls, v):
        if v is not None and any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
            raise ValueError("control_characters_prohibited")
        return v


async def _bound_scope(db, incident_id):
    incident, evidence, ctx, diagnosis = await _incident_status_scope(db, incident_id)
    candidate = diagnosis.get("candidate")
    if candidate is None:
        return incident, None, diagnosis
    return incident, str(candidate), diagnosis


async def _profile_row(db, service, target):
    row = (await db.execute(text(
        "SELECT profile, updated_by, updated_at FROM service_health_profiles "
        "WHERE service=:service AND target=:target"
    ), {"service": service, "target": target})).mappings().first()
    return dict(row) if row else None


def _profile_response(service, target, record, reason=None):
    return {
        "service": str(service or ""), "target": target,
        "configured": bool(record), "source": "sre_service_catalog" if record else "unconfigured",
        "profile": (record or {}).get("profile") or {},
        "updated_at": str(record["updated_at"]) if record else None,
        "updated_by": (record or {}).get("updated_by"),
        "reason": reason if not record else None,
        "execution_authority": False,
    }


@router.get("/incidents/{incident_id}/service-profile")
async def get_service_profile(
    incident_id: UUID, identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident, target, diagnosis = await _bound_scope(db, incident_id)
        if not target:
            return _profile_response(incident.service, None, None,
                                     diagnosis.get("reason") or "identity_unverified")
        record = await _profile_row(db, str(incident.service or "").lower().removesuffix(".service"), target)
        return _profile_response(incident.service, target, record,
                                 "not_configured" if not record else None)


@router.put(
    "/incidents/{incident_id}/service-profile",
    dependencies=[Depends(rate_limiter_strict)],
)
async def upsert_service_profile(
    incident_id: UUID, payload: ServiceHealthProfile,
    identity=Depends(require_permission("manage:service_profile")),
):
    async with AsyncSessionLocal() as db:
        incident, target, diagnosis = await _bound_scope(db, incident_id)
        if not target:
            raise HTTPException(status_code=409, detail={
                "code": "service_identity_unverified",
                "reason": diagnosis.get("reason"),
            })
        service = str(incident.service or "").strip().lower().removesuffix(".service")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,119}", service):
            raise HTTPException(status_code=409, detail="unsupported_service_name")
        profile = payload.model_dump(mode="json")
        await db.execute(text(
            "INSERT INTO service_health_profiles (service,target,profile,updated_by,updated_at) "
            "VALUES (:service,:target,CAST(:profile AS jsonb),:actor,NOW()) "
            "ON CONFLICT (service,target) DO UPDATE SET profile=EXCLUDED.profile, "
            "updated_by=EXCLUDED.updated_by, updated_at=NOW()"
        ), {"service": service, "target": target,
            "profile": __import__("json").dumps(profile), "actor": identity.subject[:180]})
        await db.commit()
        # Audit metadata contains no secrets or remote URL, and never authorizes actions.
        await PostgreSQLAuditStore(db).append({
            "event_id": str(uuid4()), "event_type": "service_health_profile_updated",
            "actor": identity.subject, "incident_id": str(incident_id),
            "action": "service_profile", "status": "recorded",
            "metadata": {"service": service, "target": target,
                         "platform": payload.platform,
                         "expected_port": payload.expected_port,
                         "health_path": payload.health_path},
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        return _profile_response(service, target, {
            "profile": profile, "updated_by": identity.subject,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })


def _health_result(events, service, target):
    for event in events:
        if event.get("event_type") != "service_http_health_rechecked":
            continue
        data = event.get("metadata") or {}
        if not isinstance(data, dict) or data.get("service") != service or data.get("target") != target:
            continue
        return {
            "status": str(data.get("status") or "unknown"),
            "http_code": data.get("http_code"),
            "checked_at": str(event.get("created_at") or ""),
            "source": "bounded_http_check", "scope": "http_health_only",
        }
    return {"status": "not_checked", "http_code": None, "checked_at": None,
            "source": "no_http_probe", "scope": "http_health_only"}


@router.get("/incidents/{incident_id}/health-status")
async def service_http_health_status(
    incident_id: UUID, identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident, target, diagnosis = await _bound_scope(db, incident_id)
        if not target:
            return {"status": "unavailable", "reason": diagnosis.get("reason"),
                    "source": "identity_unverified"}
        profile = await _profile_row(db, str(incident.service or "").lower().removesuffix(".service"), target)
        values = (profile or {}).get("profile") or {}
        if not values.get("expected_port") or not values.get("health_path"):
            return {"status": "not_configured", "source": "service_catalog"}
        events = await PostgreSQLAuditStore(db).list(str(incident_id), 200)
        return _health_result(events, str(incident.service).lower(), target)


def _safe_health_target(target):
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return False
    return (isinstance(addr, ipaddress.IPv4Address) and addr.is_private
            and not addr.is_loopback and not addr.is_link_local
            and not addr.is_multicast and not addr.is_unspecified
            and target not in {"169.254.169.254"})


@router.post(
    "/incidents/{incident_id}/health/recheck",
    dependencies=[Depends(rate_limiter_strict)],
)
async def recheck_http_health(
    incident_id: UUID, identity=Depends(require_permission("read:incident")),
):
    """Explicit bounded GET to an SRE-managed path on the incident-bound VM.

    No redirects, proxies, credentials or response body; no arbitrary URLs.
    Unapproved health values cannot grant Restart approval.
    """
    async with AsyncSessionLocal() as db:
        incident, target, diagnosis = await _bound_scope(db, incident_id)
        if not target or not _safe_health_target(target):
            raise HTTPException(status_code=409, detail="health_probe_target_not_allowed")
        row = await _profile_row(db, str(incident.service or "").lower().removesuffix(".service"), target)
        profile = (row or {}).get("profile") or {}
        path = profile.get("health_path")
        port = profile.get("expected_port")
        scheme = profile.get("health_scheme")
        if (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
                or not isinstance(path, str) or not _ALLOWED_HEALTH.fullmatch(path)
                or ".." in path or "//" in path or " " in path
                or scheme not in {"http", "https"}):
            raise HTTPException(status_code=409, detail="health_profile_not_configured")
        url = f"{scheme}://{target}:{port}{path}"
        http_code = None
        status = "unavailable"
        try:
            async with verified_async_client(
                component="service_catalog:health_recheck",
                timeout=httpx.Timeout(3.0), trust_env=False,
                follow_redirects=False, headers={"Accept": "application/json"},
            ) as client:
                response = await client.get(url)
                http_code = response.status_code
            status = "healthy" if 200 <= http_code < 300 else "unhealthy"
        except httpx.RequestError:
            status = "unavailable"
        checked = datetime.now(timezone.utc)
        await PostgreSQLAuditStore(db).append({
            "event_id": str(uuid4()), "event_type": "service_http_health_rechecked",
            "actor": identity.subject, "incident_id": str(incident_id),
            "action": "http_health_read", "status": "recorded",
            "metadata": {"service": str(incident.service).lower(), "target": target,
                         "status": status, "http_code": http_code},
            "created_at": checked.isoformat(),
        })
        return {"status": status, "http_code": http_code,
                "checked_at": checked.isoformat(),
                "source": "bounded_http_check", "scope": "http_health_only"}
