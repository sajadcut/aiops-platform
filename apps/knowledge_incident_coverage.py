"""One non-publishing, human-reviewable diagnostic case per durable incident.

Distinct from verified recovery knowledge: an unresolved/blocked/no-action case
is a useful *question for human review*, never a proven RCA or an executable
runbook. No MCP or Cognia call occurs in this module.
"""
from __future__ import annotations

import json
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5

from fastapi import HTTPException
from sqlalchemy import select, text

from apps.knowledge_review import configured_kb, content_digest, validated_document
from apps.knowledge_review_dossier import incident_dossier
from domain.contracts.config import settings
from domain.contracts.redaction import redact_text
from domain.models import Evidence, Finding, Incident, KnowledgeReview


def coverage_review_id(incident_id: UUID) -> UUID:
    return uuid5(NAMESPACE_URL, f"aiops:incident-coverage:v1:{incident_id}")


def _safe(value: object, limit: int = 180) -> str:
    return redact_text(str(value or "ثبت نشده").replace("\n", " ").replace("\r", " "))[:limit]


def incident_coverage_document(
    incident: Incident, *, evidence: list, findings: list, dossier: dict,
) -> tuple[str, str]:
    """Use *recorded* incident fields and scoped refs, not arbitrary MCP output."""
    state = str(getattr(incident.status, "value", incident.status) or "unknown").lower()
    service = _safe(incident.service or "نامشخص", 100)
    source = _safe(incident.source, 80)
    title = (f"رخداد {service} · {source} · {state} · "
             f"{str(incident.id)[:8]} (تصمیم بازبین)")
    body = [
        "نوع: تجربهٔ تشخیصی رخداد برای تصمیم انسانی؛ دانش تأییدشده نیست.",
        f"شناسه رخداد: {incident.id}",
        f"سرویس: {service}",
        f"منبع هشدار: {source}",
        f"شدت ثبت‌شده: {_safe(incident.severity, 40)}",
        f"وضعیت ثبت‌شدهٔ رخداد هنگام تهیهٔ پیش‌نویس: {state}",
        "خلاصهٔ هشدار اولیه (ادعای منبع، نه علت اثبات‌شده): "
        + _safe(incident.summary, 450),
        f"تعداد شواهد منتخب برای بازبینی: {len(evidence)}",
        "شواهد دارای شناسه و منشأ (جزئیات خام وارد دانش نمی‌شود):",
    ]
    for e in evidence[:12]:
        kind = str(getattr(e.type, "value", e.type) or "unknown")
        body.append(f"- {_safe(e.source, 45)} / {_safe(kind, 30)} / "
                    f"{str(e.id)[:36]}")
    if not evidence:
        body.append("- شواهد مستقل در نمونهٔ بررسی‌شده موجود نیست؛ نیازمند بررسی بیشتر.")
    body.append("یافته‌های Agent (فرضیه، نه اثبات مستقل):")
    if findings:
        for finding in findings[:6]:
            body.append(f"- {_safe(finding.agent, 65)}: "
                        f"{_safe(finding.statement, 260)}")
    else:
        body.append("- یافته‌ای ثبت نشده است؛ علت ریشه‌ای نامعلوم است.")
    if dossier.get("facts"):
        body.append("مشاهدات فنی مستقل مربوط به همین رخداد:")
        for fact in dossier["facts"][:7]:
            body.append("- " + _safe(fact, 300))
    if dossier.get("monitor_recovered") is True:
        body.append("وضعیت بازیابی: Recovery معتبر منبع مانیتورینگ ثبت شده است.")
    elif dossier.get("independent_recovery_verified") is True:
        body.append("وضعیت بازیابی: بررسی مستقل systemd ثبت شده؛ Recovery منبع مانیتورینگ اثبات نشده است.")
    else:
        body.append("وضعیت بازیابی: رفع هشدار و سلامت نهایی از شواهد این پیش‌نویس اثبات نشده است.")
    body.extend([
        "علت ریشه‌ای قطعی: فقط در صورت وجود شواهد مستقل توسط بازبین تعیین شود.",
        "اقدام پیشنهادی/مسدود/ناموفق با اجرای واقعی و راستی‌آزمایی یکسان نیست.",
        "پیش از ذخیره، شواهد و اقدام واقعی را بازبینی، متن را در صورت لزوم ویرایش یا رد کنید.",
        "انتشار به Cognia تنها پس از تأیید انسانی؛ این تجربه مجوز اجرای عملیاتی نیست.",
    ])
    return validated_document(title, "\n".join(body))


async def _source_document(db, incident: Incident) -> tuple[str, str]:
    evidence = (await db.execute(
        select(Evidence).where(Evidence.incident_id == incident.id)
        .order_by(Evidence.created_at.desc()).limit(12)
    )).scalars().all()
    findings = (await db.execute(
        select(Finding).where(Finding.incident_id == incident.id)
        .order_by(Finding.created_at.desc()).limit(6)
    )).scalars().all()
    dossier = await incident_dossier(db, incident.id)
    return incident_coverage_document(
        incident, evidence=evidence, findings=findings, dossier=dossier,
    )


async def create_from_incident(db, incident_id: UUID) -> tuple[KnowledgeReview | None, str]:
    """Stable ID. Refresh only untouched system drafts; preserve human decisions."""
    identifier = coverage_review_id(incident_id)
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:lock))"),
                     {"lock": f"knowledge:incident-coverage:{incident_id}"})
    existing = await db.get(KnowledgeReview, identifier)
    if existing is not None:
        # The incident can later recover or fail after its first analysis.
        # Update the pending, system-owned draft, but NEVER rewrite operator
        # edits, approvals, rejects or previously published revisions.
        pristine = (
            existing.created_by == "system:incident-coverage"
            and existing.review_reason == "incident_coverage:v1"
            and existing.status == "pending_review"
            and existing.reviewed_by is None
            and existing.approved_hash is None
            and existing.content_hash == content_digest(existing.title, existing.content)
        )
        if pristine:
            source = await db.get(Incident, incident_id)
            if source is not None:
                title, content = await _source_document(db, source)
                digest = content_digest(title, content)
                if digest != existing.content_hash:
                    existing.title, existing.content = title, content
                    existing.content_hash = digest
                    existing.revision = int(existing.revision or 1) + 1
                    await db.execute(text("""
                        INSERT INTO audit_events
                          (event_id,event_type,actor,incident_id,action,status,metadata,created_at)
                        VALUES (:event_id,'knowledge_evidence_refreshed',:actor,:incident_id,
                          'refreshed','pending_review',CAST(:metadata AS jsonb),now())
                    """), {
                        "event_id": uuid4(), "actor": "system:incident-coverage",
                        "incident_id": incident_id,
                        "metadata": json.dumps({
                            "review_id": str(identifier), "revision": existing.revision,
                            "content_hash": digest, "source": "incident_coverage",
                        }),
                    })
                    await db.commit()
                    return existing, "updated"
        return existing, "existing"
    incident = await db.get(Incident, incident_id)
    if incident is None:
        return None, "incident_not_found"
    # Other recovery/follow-up/config reviews already give the operator an
    # explicit choice for this incident. Never recreate a rejected/published
    # case or overwrite a human-edited revision.
    any_review = (await db.execute(
        select(KnowledgeReview).where(KnowledgeReview.incident_id == incident_id)
        .order_by(KnowledgeReview.created_at.desc()).limit(1)
    )).scalars().first()
    if any_review is not None:
        return any_review, "existing"
    kb_id = configured_kb()
    app_id = int(settings.COGNIA_CLIENT_APPLICATION_ID or 0)
    if app_id <= 0:
        raise HTTPException(503, "cognia_client_application_id_not_configured")
    title, content = await _source_document(db, incident)
    record = KnowledgeReview(
        id=identifier, incident_id=incident_id, memory_id=None,
        source_type="incident_followup", kb_id=kb_id,
        scope={"type": "clientApplication", "clientApplicationId": app_id},
        title=title, content=content, content_hash=content_digest(title, content),
        status="pending_review", revision=1, created_by="system:incident-coverage",
        review_reason="incident_coverage:v1",
    )
    db.add(record)
    await db.flush()
    await db.execute(text("""
        INSERT INTO audit_events
          (event_id,event_type,actor,incident_id,action,status,metadata,created_at)
        VALUES (:event_id,'knowledge_drafted',:actor,:incident_id,
          'drafted','pending_review',CAST(:metadata AS jsonb),now())
    """), {
        "event_id": uuid4(), "actor": "system:incident-coverage",
        "incident_id": incident_id,
        "metadata": json.dumps({
            "review_id": str(identifier), "source": "incident_coverage",
            "kb_id": kb_id, "content_hash": record.content_hash,
        }),
    })
    await db.commit()
    return record, "created"


async def draft_incident_best_effort(incident_id: str) -> None:
    """Run *after* incident commit; knowledge failures must not break ingestion."""
    from database import AsyncSessionLocal
    from domain.contracts.logging import logger

    if not settings.COGNIA_KNOWLEDGE_BASE_IDS or not settings.COGNIA_CLIENT_APPLICATION_ID:
        logger.info("incident_knowledge_draft_not_configured", incident_id=incident_id)
        return
    try:
        async with AsyncSessionLocal() as session:
            await create_from_incident(session, UUID(str(incident_id)))
    except Exception as exc:
        logger.warning("incident_knowledge_draft_failed",
                       incident_id=incident_id, error_type=type(exc).__name__)
