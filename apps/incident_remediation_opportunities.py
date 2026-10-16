"""Evidence-scoped remediation opportunities for a multi-finding Incident.

A diagnosis is NOT an executable proposal. Each independent problem gets a
separate next step, coverage/authority status and explicit blocker. Never
construct Approval objects or shell commands from monitoring/LLM evidence.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def build_remediation_opportunities(*, incident: Mapping[str, Any],
                                    evidence: Iterable[dict], report: dict) -> list[dict]:
    rows = [row for row in evidence if isinstance(row, dict)]
    summary = report.get("incident_summary") or {}
    target = str(summary.get("target") or "").strip()
    service = str(incident.get("service") or "").lower().removesuffix(".service")
    approval = report.get("approval_readiness") or {}
    config = report.get("configuration_diagnostic") or {}
    opportunities: list[dict] = []

    config_invalid = config.get("status") == "invalid"
    if config_invalid:
        candidates = (report.get("dynamic_investigation") or {}).get("config_proposal") or {}
        candidate_ready = candidates.get("status") == "candidate_proposed"
        opportunities.append({
            "id": "configuration_syntax",
            "title_fa": "اصلاح خطای سینتکس کانفیگ",
            "title_en": "Configuration syntax repair",
            "status": "approval_path_available" if candidate_ready else "candidate_required",
            "finding_fa": "Validator خطای ساختار فایل تنظیمات را ثبت کرده است.",
            "finding_en": "The config parser reported invalid syntax.",
            "remediation_fa": "بازبینی Diff، اعتبارسنجی نسخهٔ اصلاحی، Approval مستقل، سپس اعمال و بررسی نتیجه.",
            "remediation_en": "Review diff, validate candidate, seek independent approval, apply and verify.",
            "blocker_fa": None if candidate_ready else "هنوز نسخهٔ اصلاحی قابل‌اعتبارسنجی موجود نیست.",
            "blocker_en": None if candidate_ready else "No valid repair candidate is available yet.",
            "action": "config_review",
            "approval_id": approval.get("approval_id"),
            "execution_authorized": False,
        })

    latest_status = None
    for item in rows:
        raw = item.get("raw_data") or {}
        if (item.get("source") != "vm_mcp" or not isinstance(raw, dict)
                or raw.get("diagnostic") != "service_status"
                or raw.get("success") is not True
                or (target and raw.get("target") != target)
                or str(raw.get("service") or "").lower().removesuffix(".service") != service):
            continue
        stamp = str(item.get("created_at") or "")
        if latest_status is None or stamp > latest_status[0]:
            latest_status = (stamp, raw)
    if latest_status is not None:
        state = latest_status[1].get("active_state")
        sub = latest_status[1].get("sub_state")
        if state in {"failed", "inactive"} or (state == "activating" and sub == "auto-restart"):
            opportunities.append({
                "id": "systemd_recovery",
                "title_fa": "بازیابی سرویس systemd",
                "title_en": "Systemd service recovery",
                "status": "independent_approval_required",
                "finding_fa": "شواهد ثبت‌شده سرویس را Down یا در چرخهٔ Restart نشان می‌دهند.",
                "finding_en": "Recorded systemd evidence shows Down or an auto-restart loop.",
                "remediation_fa": "پس از اصلاح علت، دو استعلام زنده، پیش‌شرط‌های سرویس و Approval مستقل Start/Restart بررسی شوند.",
                "remediation_en": "After fixing the cause, check fresh systemd observations, prerequisites and independent Start/Restart approval.",
                "blocker_fa": "Start/Restart از تشخیص خطا مجوز نمی‌گیرد؛ سلامت Runtime هنوز جداگانه تأیید نشده است.",
                "blocker_en": "Detection is not authority for Start/Restart; runtime readiness is unverified.",
                "action": "service_recheck",
                "execution_authorized": False,
            })

    # Filesystem capacity is *not* a verdict on causality or deletion safety.
    # Only VM MCP records for the bound host (never model text) can open this card.
    mounts: dict[str, dict] = {}
    for item in rows:
        raw = item.get("raw_data") or {}
        if (item.get("source") != "vm_mcp" or not isinstance(raw, dict)
                or raw.get("diagnostic") != "disk_status"
                or raw.get("success") is not True
                or not target or raw.get("target") != target):
            continue
        for fs in raw.get("filesystems") or []:
            if not isinstance(fs, dict):
                continue
            mount = str(fs.get("mount") or "")
            if not mount.startswith("/") or len(mount) > 120:
                continue
            try:
                used = float(str(fs.get("use_percent") or "").strip().removesuffix("%"))
            except (ValueError, TypeError):
                continue
            if used < 95 or used > 100:
                continue
            when = str(item.get("created_at") or "")
            if mount not in mounts or when > mounts[mount]["at"]:
                mounts[mount] = {"mount": mount, "percent": used, "at": when}
    for item in sorted(mounts.values(), key=lambda x: (-x["percent"], x["mount"]))[:3]:
        mount = item["mount"]
        opportunities.append({
            "id": "filesystem_pressure:" + mount,
            "title_fa": "رفع فشار فضای دیسک " + mount,
            "title_en": "Filesystem capacity pressure " + mount,
            "status": "executor_unavailable",
            "finding_fa": f"مصرف ثبت‌شدهٔ Mount {mount}: {item['percent']:g}٪.",
            "finding_en": f"Recorded usage of {mount}: {item['percent']:g}%.",
            "remediation_fa": "منشأ رشد، تنظیمات logrotate، فایل‌های باز، محدودیت نگهداری و خطاهای ENOSPC را بررسی کنید؛ سپس برای تغییر مشخص Runbook و Approval جدا تعریف شود.",
            "remediation_en": "Check writers, rotation, open handles, retention and ENOSPC; a scoped runbook and separate approval are required for a concrete change.",
            "blocker_fa": "ابزار امن اجرای پاک‌سازی/Logrotate با قرارداد و Rollback در این MCP موجود نیست؛ حذف خودکار مجاز نیست.",
            "blocker_en": "No governed cleanup/logrotate executor with rollback is available; automatic deletion is forbidden.",
            "action": "disk_investigation",
            "execution_authorized": False,
        })

    # Health-check configuration is an operational gap, not a proven outage.
    # Never transform missing monitoring metadata into permission to edit a VM.
    return opportunities[:6]
