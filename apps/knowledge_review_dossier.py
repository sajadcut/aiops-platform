"""Evidence-backed technical context for Cognia Knowledge Review.

Only a compact allowlist of source facts is exposed. Never copy raw config,
journal lines, LLM prose, SSH stdout, credentials or candidate bytes into RAG.
This is a review aid, NOT proof of root cause or authority to execute.
"""
from __future__ import annotations

import re
from typing import Any, Mapping
from uuid import UUID

from sqlalchemy import select

from domain.contracts.redaction import redact_text
from domain.models import Evidence, Incident
from apps.audit_service.postgres import PostgreSQLAuditStore


_VALID_PATH = re.compile(r"^/(?:[a-zA-Z0-9_.@+-]+/)*[a-zA-Z0-9_.@+-]+$")
_BRACE = re.compile(r"unexpected\s*[\"'“]?\{", re.IGNORECASE)


def _safe_path(value: Any) -> str | None:
    path = value if isinstance(value, str) else ""
    if len(path) > 220 or not _VALID_PATH.fullmatch(path):
        return None
    path = redact_text(path)
    return path if _VALID_PATH.fullmatch(path) else None


def _same_service(observed: Any, service: str) -> bool:
    return (isinstance(observed, str)
            and observed.lower().removesuffix(".service")
            == service.lower().removesuffix(".service"))


def build_dossier(
    *, incident_id: str, service: str, incident_status: str,
    evidence: list[Mapping[str, Any]],
    audits: list[Mapping[str, Any]],
    source_recovery: Mapping[str, Any] | None = None,
) -> dict:
    """Extract sourced, scoped and bounded facts for the selected incident.

    Records must already be restricted by the DB query to incident_id.
    Returned facts deliberately do not conflate file verification, systemd
    activation, and authoritative Zabbix/monitor recovery.
    """
    invalid = None
    live_status = None
    service = service.lower().removesuffix(".service")
    for item in evidence[:200]:  # newest first
        if str(item.get("source") or "").lower() != "vm_mcp":
            continue
        raw = item.get("raw_data") or {}
        if not isinstance(raw, dict) or not _same_service(raw.get("service"), service):
            continue
        diagnostic = str(raw.get("diagnostic") or "")
        if (live_status is None and diagnostic == "service_status"
                and raw.get("success") is True
                and raw.get("active_state") in {"failed", "inactive", "active"}):
            live_status = {
                "active_state": raw["active_state"],
                "evidence_ref": str(item.get("id") or "")[:64],
            }
        if (invalid is None and diagnostic == "config_validate"
                and raw.get("success") is True
                and raw.get("supported") is True
                and raw.get("valid") is False):
            path = _safe_path(raw.get("config_file"))
            line = raw.get("error_line")
            if path and type(line) is int and 1 <= line <= 1000000:
                err = str(raw.get("syntax_error") or raw.get("detail") or "")
                invalid = {
                    "config_file": path, "error_line": line,
                    "error_kind": ("unexpected_opening_brace"
                                   if _BRACE.search(err) else "vendor_syntax_error"),
                    "evidence_ref": str(item.get("id") or "")[:64],
                }

    applied = None
    for item in audits[:200]:  # newest first
        if (item.get("event_type") != "configuration_change_transition"
                or item.get("status") != "applied_config_vendor_verified"):
            continue
        meta = item.get("metadata") or {}
        if not isinstance(meta, dict):
            continue
        if meta.get("production_write_performed") is not True:
            continue
        applied = {
            "config_apply": "vendor_verified",
            "approval_id": str(meta.get("approval_id") or "")[:80],
            "systemd_recovery": (
                "active" if meta.get("service_recovery_confirmed") is True
                else "not_confirmed"),
            "service_start_attempted": meta.get("service_start_attempted") is True,
            "audit_ref": str(item.get("event_id") or "")[:64],
        }
        break

    recovered = isinstance(source_recovery, Mapping) and (
        source_recovery.get("source") == "zabbix"
        and source_recovery.get("incident_resolved") is True
        and incident_status.lower() == "resolved")
    facts = []
    if invalid:
        facts.append(
            f"خطای نحوی مشاهده‌شده: فایل {invalid['config_file']}، خط "
            f"{invalid['error_line']}؛ نوع خطا: "
            + ("آکولاد باز غیرمنتظره" if invalid["error_kind"] == "unexpected_opening_brace"
               else "خطای نحوی گزارش‌شده توسط ابزار سرویس")
            + f"؛ شاهد: {invalid['evidence_ref']}"
        )
    if applied:
        facts.append(
            "اعمال فایل: با موفقیت و اعتبارسنجی پس از اعمال توسط ابزار سرویس ثبت شده؛ "
            f"Approval: {applied['approval_id']}؛ Audit: {applied['audit_ref']}"
        )
        facts.append(
            "وضعیت بازیابی در زمان ثبت اجرا: "
            + ("فعال‌شدن systemd تأیید شده؛ هنوز معادل Recovery مانیتورینگ نیست"
               if applied["systemd_recovery"] == "active" else
               "فعال‌شدن سرویس پس از اصلاح در این رکورد تأیید نشده")
        )
    elif invalid:
        facts.append("اعمال نسخهٔ اصلاحی: نتیجهٔ موفقِ مستند در Audit یافت نشد.")
    if live_status:
        facts.append(
            f"وضعیت ثبت‌شدهٔ systemd: {live_status['active_state']} "
            f"(شاهد: {live_status['evidence_ref']}؛ ممکن است قدیمی باشد)"
        )
    facts.append(
        "وضعیت رفع رخداد در منبع مانیتورینگ: "
        + ("Recovery معتبر Zabbix ثبت و رخداد Resolved شده است"
           if recovered else "برای این رخداد تأیید نشده است")
    )
    return {
        "incident_id": incident_id, "service": service,
        "config_diagnostic": invalid, "config_execution": applied,
        "systemd_observation": live_status,
        "monitor_recovered": bool(recovered),
        "incident_status": incident_status.lower(),
        "facts": facts[:7],
        "source": "incident_evidence_and_audit",
        "not_execution_authority": True,
    }


async def incident_dossier(db, incident_id: UUID) -> dict:
    """Read the exact incident's durable evidence and audit; no external calls."""
    row = await db.get(Incident, incident_id)
    if row is None:
        return {}
    evidence_rows = (await db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id)
        .order_by(Evidence.created_at.desc()).limit(200)
    )).scalars().all()
    audits = await PostgreSQLAuditStore(db).list(str(incident_id), limit=200)
    context = row.context if isinstance(row.context, dict) else {}
    source_recovery = context.get("source_recovery")
    status = getattr(row.status, "value", row.status)
    return build_dossier(
        incident_id=str(incident_id),
        service=str(row.service or "unknown"),
        incident_status=str(status or "unknown"),
        evidence=[{"id": item.id, "source": item.source,
                   "raw_data": item.raw_data} for item in evidence_rows],
        audits=audits, source_recovery=source_recovery,
    )


def dossier_addendum(dossier: Mapping[str, Any] | None) -> str:
    """Knowledge-safe exact operational facts, distinct from inferred RCA."""
    if not isinstance(dossier, Mapping) or not dossier.get("config_diagnostic"):
        return ""
    facts = [str(x) for x in (dossier.get("facts") or []) if isinstance(x, str)]
    return "\n".join([
        "شواهد فنی مرتبط با کانفیگ (ثبت‌شده؛ نه دستورات اجرایی):",
        *["- " + fact for fact in facts[:7]],
        "تمایز ضروری: گذر تست فایل با بالا آمدن سرویس و رفع آلارم یکسان نیست.",
        "قبل از استفادهٔ مجدد، خطا و وضعیت سرویس باید دوباره بررسی و "
        "هرگونه عملیات جداگانه تأیید شود.",
    ])


def dossier_title(service: str, dossier: Mapping[str, Any] | None,
                  *, verified_memory: bool = False) -> str | None:
    """Meaningful candidate label rather than ten indistinguishable titles."""
    if not isinstance(dossier, Mapping):
        return None
    diagnostic = dossier.get("config_diagnostic")
    if not isinstance(diagnostic, Mapping):
        return None
    path = diagnostic.get("config_file")
    line = diagnostic.get("error_line")
    if not isinstance(path, str) or type(line) is not int:
        return None
    # Keep filenames relevant but never assert that a stale error persists.
    suffix = "تجربهٔ ثبت‌شده" if verified_memory else "نیازمند بازبینی"
    return redact_text(f"{service}: خطای کانفیگ {path}:{line} ({suffix})")[:500]
