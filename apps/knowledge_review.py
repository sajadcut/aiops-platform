"""Approved organizational knowledge pipeline; not an operational-execution gate.

Operational Memory stays in PostgreSQL. Only reviewed/approved documents cross
the separate Cognia Knowledge boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL

from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from domain.contracts.config import settings
from domain.contracts.redaction import redact_text
from domain.models import KnowledgeReview, MemoryEntry, Incident


def content_digest(title: str, content: str) -> str:
    return hashlib.sha256((title + "\n" + content).encode("utf-8")).hexdigest()


def validated_document(title: str, content: str) -> tuple[str, str]:
    title = str(title or "").strip()
    content = str(content or "").strip()
    if not title or len(title) > 500 or not content or len(content.encode("utf-8")) > 1024 * 1024:
        raise HTTPException(422, "knowledge_title_or_content_invalid")
    # Reject rather than silently modifying reviewer-approved bytes.
    if redact_text(title) != title or redact_text(content) != content:
        raise HTTPException(422, "knowledge_contains_sensitive_material")
    return title, content


def memory_is_verified(row: MemoryEntry) -> bool:
    remediation = row.actual_remediation if isinstance(row.actual_remediation, dict) else {}
    verification = row.verification if isinstance(row.verification, dict) else {}
    provenance = row.evidence_provenance if isinstance(row.evidence_provenance, dict) else {}
    return (
        row.memory_outcome_class == "successful_recovery"
        and str(row.verification_result or "").lower() in {"success", "verified", "succeeded"}
        and str(verification.get("status") or "").lower() == "success"
        and remediation.get("execution_success") is True
        and bool(remediation.get("action"))
        and int(provenance.get("evidence_count") or 0) > 0
        and str(row.lifecycle_status or "").lower() in {"active", "validated"}
        and bool(row.incident_id)
    )


def incident_document(row: MemoryEntry, *, dossier: dict | None = None) -> tuple[str, str]:
    if not memory_is_verified(row):
        raise HTTPException(409, "verified_successful_memory_required")
    rem = row.actual_remediation
    verification = row.verification
    service = str(row.service_scope or "unknown-service")
    from apps.knowledge_review_dossier import dossier_title, dossier_addendum
    title = (dossier_title(service, dossier, verified_memory=True)
             or f"Verified incident recovery: {service}"[:500])
    # Distinguish sourced/verified facts from uncertain RCA. Never turn an
    # Agent hypothesis into a proven cause in published organizational knowledge.
    root_status = str(row.root_cause_status or "unknown").lower()
    root_cause = str(row.root_cause or "not established")
    if root_status not in {"confirmed", "verified"}:
        root_cause = "Not independently confirmed; review evidence before reuse."
    details = [
        "Type: Verified Incident Experience",
        f"Service: {service}",
        f"Incident reference: {row.incident_id}",
        f"Observed symptom pattern: {row.pattern or 'unknown'}",
        f"Root cause status: {root_status}",
        f"Root cause: {root_cause}",
        f"Approved execution action (historical): {rem.get('action')}",
        f"Runbook: {rem.get('runbook_id') or 'not recorded'}",
        f"Evidence references (historical): {', '.join(str(ref)[:200] for ref in (row.evidence_provenance or {}).get('evidence_refs', [])[:10]) or 'not recorded'}",
        f"Verification status: {verification.get('status')}",
        f"Recovered signals: {', '.join(map(str, verification.get('recovered_signals') or [])) or 'not recorded'}",
        f"Outcome: {row.outcome or 'verified recovery'}",
        f"Reusable lesson: {row.reusable_lesson or ''}",
        *([dossier_addendum(dossier)] if dossier_addendum(dossier) else []),
        "Safety: historical experience only. Revalidate live evidence, blast radius,"
        " policy and approval before any remediation. Never execute from RAG alone.",
    ]
    return validated_document(title, "\n".join(details))


def configured_kb(kb_id: int | None = None) -> int:
    ids = list(settings.COGNIA_KNOWLEDGE_BASE_IDS)
    selected = int(kb_id) if kb_id is not None else (ids[0] if len(ids) == 1 else 0)
    if selected <= 0 or selected not in ids:
        raise HTTPException(422, "knowledge_kb_must_be_explicitly_configured")
    return selected


def review_summary(row: KnowledgeReview) -> dict:
    return {
        "id": str(row.id),
        "source_type": row.source_type,
        "incident_id": str(row.incident_id) if row.incident_id else None,
        "memory_id": str(row.memory_id) if row.memory_id else None,
        "kb_id": row.kb_id,
        "title": row.title,
        "content": row.content,
        "revision": row.revision,
        "status": row.status,
        "created_by": row.created_by,
        "reviewed_by": row.reviewed_by,
        "review_reason": row.review_reason,
        "approved_revision": row.approved_revision,
        "cognia_knowledge_id": row.cognia_knowledge_id,
        "cognia_revision_id": row.cognia_revision_id,
        "publish_error_code": row.publish_error_code,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


async def create_from_memory(db, memory_id: UUID, actor: str, *, kb_id: int | None = None):
    selected = configured_kb(kb_id)
    memory = await db.get(MemoryEntry, memory_id)
    if memory is None:
        raise HTTPException(404, "operational_memory_not_found")
    from apps.knowledge_review_dossier import incident_dossier
    dossier = await incident_dossier(db, memory.incident_id) if memory.incident_id else {}
    title, content = incident_document(memory, dossier=dossier)
    existing = (await db.execute(
        select(KnowledgeReview).where(KnowledgeReview.memory_id == memory_id)
    )).scalars().first()
    if existing:
        return existing
    # Repeated memory episodes for a single incident must not create a row of
    # indistinguishable, simultaneously pending "Verified incident recovery"
    # candidates. Keep the first for review; do not modify approved documents.
    pending_incident = (await db.execute(
        select(KnowledgeReview).where(
            KnowledgeReview.incident_id == memory.incident_id,
            KnowledgeReview.source_type == "incident",
            KnowledgeReview.status == "pending_review",
        ).order_by(KnowledgeReview.created_at.asc()).limit(1)
    )).scalars().first()
    if pending_incident:
        return pending_incident
    record = KnowledgeReview(
        source_type="incident", memory_id=memory.id,
        incident_id=memory.incident_id, kb_id=selected,
        scope={"type": "clientApplication", "clientApplicationId": int(settings.COGNIA_CLIENT_APPLICATION_ID or 0)},
        title=title, content=content, content_hash=content_digest(title, content),
        created_by=actor, status="pending_review",
    )
    if not record.scope["clientApplicationId"]:
        raise HTTPException(503, "cognia_client_application_id_not_configured")
    db.add(record)
    try:
        await db.flush()
        # Draft creation must also be durably auditable (without raw content).
        await db.execute(text("""
            INSERT INTO audit_events
            (event_id,event_type,actor,incident_id,action,status,metadata,created_at)
            VALUES (:event_id,'knowledge_drafted',:actor,:incident_id,
                    'drafted','pending_review',CAST(:metadata AS jsonb),now())
        """), {
            "event_id": uuid4(), "actor": actor,
            "incident_id": record.incident_id,
            "metadata": json.dumps({
                "review_id": str(record.id), "memory_id": str(memory_id),
                "kb_id": selected, "content_hash": record.content_hash,
            }),
        })
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = (await db.execute(
            select(KnowledgeReview).where(KnowledgeReview.memory_id == memory_id)
        )).scalars().first()
        if existing:
            return existing
        raise
    await db.refresh(record)
    return record


async def get_locked_review(db, review_id: UUID) -> KnowledgeReview:
    record = (await db.execute(
        select(KnowledgeReview).where(KnowledgeReview.id == review_id).with_for_update()
    )).scalars().first()
    if record is None:
        raise HTTPException(404, "knowledge_review_not_found")
    return record


async def create_from_verified_config_apply(db, *, incident_id: UUID,
                                            approval_id: str) -> KnowledgeReview | None:
    """Draft a sourced lesson after real config apply, not false service recovery.

    Only a pending human-reviewed Cognia candidate is created; no publication,
    no new operational authority. Never duplicate one approved config action.
    """
    from apps.knowledge_review_dossier import (
        dossier_addendum, dossier_title, incident_dossier,
    )
    existing = (await db.execute(
        select(KnowledgeReview).where(
            KnowledgeReview.incident_id == incident_id,
            KnowledgeReview.source_type == "incident_followup",
            KnowledgeReview.review_reason == "config_apply:" + approval_id,
        ).limit(1)
    )).scalars().first()
    if existing:
        return existing
    dossier = await incident_dossier(db, incident_id)
    execution = dossier.get("config_execution") or {}
    # A vendor-success signal without the matching approval audit is not
    # authority to describe an action as performed.
    if (execution.get("config_apply") != "vendor_verified"
            or execution.get("approval_id") != approval_id):
        return None
    selected = configured_kb()
    if not settings.COGNIA_CLIENT_APPLICATION_ID:
        return None
    service = str(dossier.get("service") or "unknown")
    title = dossier_title(service, dossier) or (
        f"{service}: اصلاح کانفیگ اعمال و تأیید شد (وضعیت سرویس نیازمند بررسی)"
    )
    content = "\n".join([
        "نوع: گزارش فنی رخداد برای بازبینی انسانی؛ نه مجوز اجرا.",
        f"سرویس: {redact_text(service)}",
        f"رخداد: {incident_id}",
        f"Approval اعمال‌شده: {redact_text(approval_id)}",
        dossier_addendum(dossier) or
            "ثبت اجرای اصلاح در ممیزی تأیید شده، ولی خطای اولیه از شواهد قابل استخراج نبود.",
        "این گزارش نتیجهٔ بررسی فایل را از بازیابی systemd و رفع آلارم "
        "توسط منبع مانیتورینگ تفکیک می‌کند.",
        "انتشار به Cognia فقط پس از تأیید بازبین انسانی است.",
    ])
    title, content = validated_document(title, content)
    record = KnowledgeReview(
        id=uuid4(), source_type="incident_followup", incident_id=incident_id,
        kb_id=selected,
        scope={"type": "clientApplication",
               "clientApplicationId": int(settings.COGNIA_CLIENT_APPLICATION_ID)},
        title=title, content=content, content_hash=content_digest(title, content),
        status="pending_review", created_by="system:config-apply",
        review_reason="config_apply:" + approval_id,
    )
    db.add(record)
    await db.flush()
    await db.execute(text("""
        INSERT INTO audit_events
        (event_id,event_type,actor,incident_id,action,status,metadata,created_at)
        VALUES (:event_id,'knowledge_drafted',:actor,:incident_id,
                'drafted','pending_review',CAST(:metadata AS jsonb),now())
    """), {
        "event_id": uuid4(), "actor": "system:config-apply",
        "incident_id": incident_id,
        "metadata": json.dumps({
            "review_id": str(record.id), "approval_id": approval_id,
            "kb_id": selected, "content_hash": record.content_hash,
            "source_type": "incident_followup",
        }),
    })
    await db.commit()
    await db.refresh(record)
    return record


# Stable UUID keeps the Approval-to-draft binding even after the reviewer edits
# review_reason, and across retries, restarts, and historic audit reconciliation.
def recovery_review_id(incident_id: UUID, approval_id: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"aiops:service-recovery:v1:{incident_id}:{approval_id}")


def governed_recovery_document(incident: Incident, event: dict, approval_id: str) -> tuple[str, str] | None:
    """Only recorded, executed, scoped service writes can yield draft lessons.

    A successful executor response is not proof of incident recovery: preserve
    the independent runbook verdict and missing objectives without LLM claims.
    Never accept an arbitrary user-supplied narrative or raw SSH output.
    """
    if event.get("event_type") != "remediation_executed":
        return None
    meta = event.get("metadata") or {}
    if not isinstance(meta, dict) or str(meta.get("approval_id") or "") != approval_id:
        return None
    result = meta.get("result") or {}
    before = meta.get("precondition") or {}
    check = meta.get("verification") or {}
    if not all(isinstance(item, dict) for item in (result, before, check)):
        return None
    action = str(event.get("action") or "")
    service = str(incident.service or "")
    target = str(result.get("target") or "")
    if (action not in {"restart_service", "start_service", "reload_service"}
            or result.get("action") != action
            or result.get("success") is not True
            or result.get("execution_blocked") is True
            or before.get("safe_to_execute") is not True
            or before.get("action") != action
            or str(before.get("target") or "") != target
            or str(before.get("service") or "").lower().removesuffix(".service")
               != service.lower().removesuffix(".service")
            or not re.fullmatch(r"[a-zA-Z0-9@_.:-]{1,100}", service)
            or not re.fullmatch(r"[a-zA-Z0-9_.:-]{2,255}", target)
            or str(check.get("status") or "").lower() not in {
                "success", "partial", "inconclusive", "failed"
            }):
        return None
    # A verification message alone is not evidence. Require post-action
    # objective outcomes and at least one recorded VM/runbook evidence ref.
    objectives = check.get("objective_results") or []
    refs = check.get("evidence_refs") or []
    if not isinstance(objectives, list) or not objectives or not isinstance(refs, list):
        return None
    allowed_objectives = {"service_active", "port_listening", "tcp_reachable"}
    outcomes = []
    for item in objectives[:12]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("target") or "")
        if name not in allowed_objectives:
            continue
        actual = item.get("actual")
        if actual not in (None, True, False, 0, 1, 0.0, 1.0):
            actual = None
        passed = item.get("passed") is True and actual is not None
        outcomes.append((name, passed, actual))
    if not outcomes or not any(isinstance(ref, str) and
        ref.startswith(("runbook:pre:", "runbook:post:")) and
        len(ref) <= 250 for ref in refs):
        return None
    status = str(check["status"]).lower()
    fully_verified = (status == "success" and check.get("required_objectives_met") is True
                      and all(passed for _, passed, _ in outcomes))
    target_label = {"restart_service": "Restart", "start_service": "Start",
                    "reload_service": "Reload"}[action]
    state = ("راستی‌آزمایی مستقل کامل" if fully_verified else
             "راستی‌آزمایی ناقص؛ بازیابی کامل اثبات نشده")
    title = f"{service}: اجرای {target_label} ثبت شد؛ {state} (بازبینی انسانی)"
    facts = [
        "نوع: تجربهٔ اجرای واقعی تحت Approval؛ پیش‌نویس برای بازبینی انسانی.",
        f"سرویس: {service}",
        f"مقصد: {target}",
        f"رخداد: {incident.id}",
        f"شناسهٔ Approval: {approval_id}",
        f"عملیات اجراشده: {action}",
        "اجرای عملیات: موفق طبق پاسخ ابزار اجرایی؛ به معنی رفع قطعی رخداد نیست.",
        f"وضعیت راستی‌آزمایی مستقل: {status}",
        f"همهٔ اهداف الزامی تأیید شدند: {'بله' if fully_verified else 'خیر'}",
    ]
    translated = {"service_active": "وضعیت فعال systemd",
                  "port_listening": "گوش‌دادن روی پورت موردانتظار",
                  "tcp_reachable": "اتصال TCP"}
    for name, passed, actual in outcomes:
        readable = ("تأیید شد" if passed else "شاهد کافی ثبت نشده یا هدف محقق نشده")
        facts.append(f"هدف {translated[name]}: {readable}"
                     + ("؛ مقدار ثبت‌شده: فعال" if actual in (True, 1, 1.0)
                        else "؛ مقدار ثبت‌شده: غیرفعال" if actual in (False, 0, 0.0)
                        else "؛ بدون مقدار قابل استناد"))
    facts.extend([
        "علت ریشه‌ای: با این اجرای Restart به‌تنهایی تأیید نشده است.",
        "وضعیت رفع آلارم اصلی: در نتیجهٔ این اجرای Runbook به‌صورت مستقل اثبات نشده است.",
        "برای استفادهٔ مجدد، وضعیت فعلی سرویس، پورت، وابستگی‌ها و "
        "سیاست تغییر باید دوباره بررسی شوند. این دانش مجوز اجرای عملیات نیست.",
        "ارسال به Cognia تنها پس از بازبینی و تأیید انسانی مجاز است.",
    ])
    return validated_document(title, "\n".join(facts))


async def create_from_governed_service_recovery(
    db, *, incident_id: UUID, approval_id: str,
) -> KnowledgeReview | None:
    """Recover missed drafts from durable, incident-bound remediation audit.

    This does not re-run or re-approve a remediation and never publishes to
    Cognia. The deterministic ID survives arbitrary human changes to the text.
    """
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", approval_id):
        return None
    identifier = recovery_review_id(incident_id, approval_id)
    # Guard concurrent reconcilers, including a new execution racing the UI.
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:lock))"),
                     {"lock": f"knowledge:service-recovery:{identifier}"})
    existing = await db.get(KnowledgeReview, identifier)
    if existing is not None:
        return existing
    incident = await db.get(Incident, incident_id)
    if incident is None:
        return None
    from apps.audit_service.postgres import PostgreSQLAuditStore
    audits = await PostgreSQLAuditStore(db).list(str(incident_id), limit=250)
    source = next((event for event in audits
                   if event.get("event_type") == "remediation_executed"
                   and str((event.get("metadata") or {}).get("approval_id") or "") == approval_id),
                  None)
    if source is None:
        return None
    candidate = governed_recovery_document(incident, source, approval_id)
    if candidate is None:
        return None
    selected = configured_kb()
    client_id = int(settings.COGNIA_CLIENT_APPLICATION_ID or 0)
    if client_id <= 0:
        raise HTTPException(503, "cognia_client_application_id_not_configured")
    title, content = candidate
    raw_memory_id = (source.get("metadata") or {}).get("memory_id")
    try:
        memory_id = UUID(str(raw_memory_id)) if raw_memory_id else None
    except ValueError:
        memory_id = None
    record = KnowledgeReview(
        id=identifier, source_type="incident_followup",
        incident_id=incident_id, memory_id=None,
        kb_id=selected,
        scope={"type": "clientApplication", "clientApplicationId": client_id},
        title=title, content=content, content_hash=content_digest(title, content),
        status="pending_review", created_by="system:governed-recovery",
        review_reason="service_recovery:" + approval_id,
    )
    db.add(record)
    await db.flush()
    await db.execute(text("""
        INSERT INTO audit_events
        (event_id,event_type,actor,incident_id,action,status,metadata,created_at)
        VALUES (:event_id,'knowledge_drafted',:actor,:incident_id,
                'drafted','pending_review',CAST(:metadata AS jsonb),now())
    """), {
        "event_id": uuid4(), "actor": "system:governed-recovery",
        "incident_id": incident_id,
        "metadata": json.dumps({
            "review_id": str(identifier), "approval_id": approval_id,
            "memory_id": str(memory_id) if memory_id else None,
            "kb_id": selected, "content_hash": record.content_hash,
            "source_type": "incident_followup",
            "verification_status": (source.get("metadata") or {}).get("verification", {}).get("status"),
        }),
    })
    await db.commit()
    await db.refresh(record)
    return record
