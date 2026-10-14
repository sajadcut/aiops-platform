"""Deterministic, evidence-grounded incident explanation for operators.

This report supplements, but never overrides, governed RCA, Decision,
Approval or execution. It uses ONLY live durable diagnostic records, not
model claims, knowledge retrieval or bare HTTP success status.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


def _ref(item: dict) -> str | None:
    value = item.get("id") or item.get("evidence_id") or item.get("reference")
    return str(value)[:170] if value else None


def _recent(evidence: Iterable[dict], diagnostic: str, service: str) -> tuple[dict, str | None]:
    matched = [
        item for item in evidence
        if isinstance(item, dict) and item.get("source") == "vm_mcp"
        and isinstance(item.get("raw_data"), dict)
        and item["raw_data"].get("diagnostic") == diagnostic
        and (not item["raw_data"].get("service") or
             str(item["raw_data"].get("service")).removesuffix(".service").lower() ==
             service.removesuffix(".service").lower())
    ]
    if not matched:
        return {}, None
    # Most current collection stores a created_at; use that when available.
    selected = max(matched, key=lambda x: str(x.get("created_at") or x.get("timestamp") or ""))
    return selected["raw_data"], _ref(selected)


def _dotnet(evidence: list[dict], service: str) -> dict:
    raw, ref = _recent(evidence, "dotnet_config_syntax", service)
    if raw.get("success") is not True or raw.get("supported") is not True:
        return {}
    files = []
    for value in (raw.get("files") or [])[:12]:
        if not isinstance(value, dict):
            continue
        filename = str(value.get("file") or "")[:140]
        if not filename.endswith(".json") or "/" in filename or ".." in filename:
            continue
        files.append({
            "file": filename, "status": value.get("status"),
            "line": value.get("line") if type(value.get("line")) is int else None,
            "column": value.get("column") if type(value.get("column")) is int else None,
            "reason": str(value.get("error_code") or value.get("reason") or "")[:50],
            "explanation_fa": str(value.get("explanation_fa") or "")[:250],
        })
    directory = str(raw.get("publish_directory") or "")[:260]
    invalid = next((x for x in files if x["status"] == "invalid_json_syntax"), None)
    if invalid:
        return {
            "status": "invalid", "kind": "dotnet_json",
            "config_file": (directory + "/" + invalid["file"]) if directory.startswith("/") else invalid["file"],
            "error_line": invalid["line"], "error_column": invalid["column"],
            "error_code": invalid["reason"],
            "syntax_error_fa": invalid["explanation_fa"] or "ساختار JSON نامعتبر است؛ نوع دقیق خطا ثبت نشده است.",
            "files": files, "evidence_refs": [ref] if ref else [],
            "validated_scope": "json_syntax_only",
            "remote_python_required": raw.get("remote_python_required")
                if raw.get("remote_python_required") is False else None,
            "validator_location": "aiops_worker"
                if raw.get("validator") == "aiops-local-python-json-syntax-only"
                else "not_recorded",
        }
    return {
        "status": "json_syntax_valid" if raw.get("syntax_valid") is True else "unverified",
        "kind": "dotnet_json", "config_file": None,
        "files": files, "evidence_refs": [ref] if ref else [],
        "validated_scope": "json_syntax_only",
        "remote_python_required": raw.get("remote_python_required")
            if raw.get("remote_python_required") is False else None,
        "validator_location": "aiops_worker"
            if raw.get("validator") == "aiops-local-python-json-syntax-only"
            else "not_recorded",
    }


def explain_incident(*, evidence: list[dict], service: str,
                     evaluation: Mapping[str, Any] | None = None,
                     decision: Mapping[str, Any] | None = None) -> dict:
    service = str(service or "سرویس")[:100]
    confirmed: list[dict] = []
    uncertainties: list[str] = []
    suggested: list[str] = []
    status, status_ref = _recent(evidence, "service_status", service)
    config, config_ref = _recent(evidence, "config_validate", service)
    process, process_ref = _recent(evidence, "process_status", service)
    dotnet = _dotnet(evidence, service)
    service_state = str(status.get("active_state") or "").lower()
    if status.get("success") is True and service_state in {"failed", "inactive"}:
        confirmed.append({
            "text_fa": f"سرویس {service} در systemd در وضعیت {service_state} قرار دارد.",
            "evidence_refs": [status_ref] if status_ref else [],
        })
        if status.get("result") == "timeout":
            confirmed.append({
                "text_fa": "systemd برای این سرویس نتیجهٔ Timeout ثبت کرده است؛ این موضوع به‌تنهایی علت Timeout را ثابت نمی‌کند.",
                "evidence_refs": [status_ref] if status_ref else [],
            })
    if process.get("success") is True and process.get("running") is False:
        confirmed.append({
            "text_fa": "فرایند مورد بررسی توسط ابزار VM در حال اجرا مشاهده نشده است.",
            "evidence_refs": [process_ref] if process_ref else [],
        })
    if dotnet.get("status") == "invalid":
        loc = dotnet["config_file"]
        line = dotnet.get("error_line")
        column = dotnet.get("error_column")
        suffix = ("، خط " + str(line)) if line is not None else ""
        suffix += ("، ستون " + str(column)) if column is not None else ""
        confirmed.append({
            "text_fa": f"ساختار JSON فایل {loc}{suffix} نامعتبر است. {dotnet['syntax_error_fa']}",
            "evidence_refs": dotnet["evidence_refs"],
        })
        uncertainties.append("ارتباط مستقیم خطای JSON با علت توقف یا Timeout سرویس هنوز با شواهد اجرای برنامه اثبات نشده است.")
        suggested.extend([
            "بررسی خط گزارش‌شده و خط قبل در فایل appsettings؛ ارائهٔ اصلاح حداقلی بدون افشای مقادیر محرمانه.",
            "اعمال هر تغییر صرفاً با فرایند تغییرات و تأیید اپراتور؛ سپس اجرای دوبارهٔ Validator و کنترل لاگ Startup.",
            "فقط پس از تأیید سلامت کانفیگ و پیش‌شرط‌های اجرایی، پیشنهاد Start سرویس و Verification مستقل.",
        ])
    elif config.get("success") is True and config.get("supported") is True and config.get("valid") is False:
        path = str(config.get("config_file") or "فایل کانفیگ نامشخص")[:300]
        line = config.get("error_line")
        confirmed.append({
            "text_fa": f"بررسی سینتکس کانفیگ {path}" +
                       (f" در خط {line}" if type(line) is int else "") + " ناموفق است.",
            "evidence_refs": [config_ref] if config_ref else [],
        })
        uncertainties.append("خطای کانفیگ به‌تنهایی علت توقف اولیه را اثبات نمی‌کند.")
        suggested.extend([
            "بررسی فایل و خط گزارش‌شده، اصلاح کنترل‌شده و اجرای مجدد Validator.",
            "پس از موفقیت اعتبارسنجی، بررسی پیش‌شرط‌ها و در صورت لزوم درخواست Approval برای Start.",
        ])
    elif config.get("supported") is False:
        uncertainties.append("روش عمومی اعتبارسنجی کانفیگ این سرویس پشتیبانی نشده است.")
        suggested.append("شناسایی ابزار معتبر تست کانفیگ از systemd و مستندات Runtime؛ تا تأیید واقعی، Start خودکار پیشنهاد نشود.")

    # Critical distinction: generic unsupported does NOT contradict a
    # specialized .NET JSON syntax check that has actually run and failed.
    if dotnet.get("status") == "invalid" and config.get("supported") is False:
        uncertainties = [x for x in uncertainties if "روش عمومی اعتبارسنجی" not in x]
    if not confirmed:
        uncertainties.append("شواهد کافی برای یک نتیجهٔ قطعی دربارهٔ وضعیت سرویس در این گزارش وجود ندارد.")
    if not suggested:
        suggested.append("ادامهٔ جمع‌آوری شواهد مرتبط و ثبت نتیجهٔ واقعی هر Validator و Agent؛ اجرای تغییر تا تأیید جداگانه مسدود است.")

    blocked = str((evaluation or {}).get("decision") or (evaluation or {}).get("status") or "").lower()
    decision_value = str((decision or {}).get("decision") or "").lower()
    action_ready = decision_value in {"approve_required", "approved", "execute"}
    if not action_ready:
        approval_text = "در حال حاضر اقدام اجرایی قابل تأیید ثبت نشده است؛ این گزارش پیشنهاد بررسی است، نه مجوز تغییر."
    else:
        approval_text = "فقط اقدام ثبت‌شده در Decision و پس از گذر از کنترل‌های ایمنی و Approval قابل اجرا است."
    if dotnet.get("status") == "invalid":
        headline = f"خطای معتبر در کانفیگ JSON سرویس {service} پیدا شد؛ هنوز مجوز اصلاح یا Start صادر نشده است."
    elif any("systemd" in x["text_fa"] for x in confirmed):
        headline = f"توقف سرویس {service} تأیید شد؛ علت قطعی هنوز کامل نشده است."
    else:
        headline = f"تحلیل سرویس {service} به بررسی شواهد بیشتر نیاز دارد."

    return {
        "kind": "evidence_grounded_operator_explanation",
        "headline_fa": headline,
        "confirmed_findings": confirmed[:8],
        "uncertainties_fa": uncertainties[:6],
        "next_steps_fa": suggested[:6],
        "approval_explanation_fa": approval_text,
        "configuration": dotnet or None,
        "conflicting_agent_claims_must_be_checked": True,
        "does_not_authorize_execution": True,
    }
