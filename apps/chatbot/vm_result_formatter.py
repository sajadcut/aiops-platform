"""Deterministic, fail-closed operator rendering of governed VM observations.

The LLM can explain hypotheses, but must not omit, invent or silently transform
numeric capacity facts. This module consumes only the structured tool result.
"""
from __future__ import annotations

import re
from typing import Any

_SAFE_LABEL = re.compile(r"[^\w./:@+\- ]", re.UNICODE)


def _label(value: object) -> str:
    """A bounded data label, never interpreted as instructions or markup."""
    value = str(value or "")[:180]
    value = "".join(ch for ch in value if ch.isprintable())
    return _SAFE_LABEL.sub("?", value) or "?"


def _bytes(value: object) -> str | None:
    try:
        count = int(value)
    except (ValueError, TypeError, OverflowError):
        return None
    if count < 0 or count > 2**63 - 1:
        return None
    unit, divisor = ("TiB", 1024**4) if count >= 1024**4 else (
        ("GiB", 1024**3) if count >= 1024**3 else
        (("MiB", 1024**2) if count >= 1024**2 else ("KiB", 1024))
    )
    return f"{count / divisor:.2f} {unit}" if count >= 1024 else f"{count} B"


def _percentage(value: object) -> str | None:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,2})?%?", text):
        return None
    try:
        number = float(text.rstrip("%"))
    except ValueError:
        return None
    return f"{number:g}%" if 0 <= number <= 100 else None


def render_vm_disk_status(payload: dict[str, Any], *, persian: bool = True) -> str | None:
    """Render all valid mounts, while making failed and partial reads explicit."""
    result = payload.get("result")
    if not isinstance(result, dict):
        return None
    target = _label(result.get("target"))
    source = _label(payload.get("source") or "vm_mcp")
    if result.get("success") is not True:
        error = _label(result.get("error") or "no_successful_disk_observation")
        if persian:
            return f"بررسی دیسک سرور {target} ناموفق بود (منبع: {source}؛ خطا: {error}). دادهٔ معتبری برای اعلام ظرفیت وجود ندارد."
        return f"Disk inspection failed for {target} (source: {source}; error: {error}). No capacity values were verified."

    rows = result.get("filesystems")
    if not isinstance(rows, list) or not rows:
        if persian:
            return f"ابزار {source} برای سرور {target} موفق گزارش شده، اما فهرست فایل‌سیستم‌ها خالی یا نامعتبر است؛ ظرفیت دیسک تأیید نشد."
        return f"The {source} tool reported success for {target}, but returned no valid filesystem inventory; disk capacity remains unverified."

    inode_by_mount: dict[str, str] = {}
    for item in result.get("inodes", []) if isinstance(result.get("inodes"), list) else []:
        if isinstance(item, dict) and isinstance(item.get("mount"), str):
            percent = _percentage(item.get("use_percent"))
            if percent is not None:
                inode_by_mount[item["mount"]] = percent

    observed_at = result.get("observed_at")
    if persian:
        lines = [f"وضعیت دیسک سرور {target} (منبع: {source})"]
        lines.append(f"زمان مشاهده: {_label(observed_at)}" if observed_at else "زمان مشاهده توسط ابزار ثبت نشده است.")
    else:
        lines = [f"Disk status for {target} (source: {source})"]
        lines.append(f"Observed: {_label(observed_at)}" if observed_at else "Observation timestamp not supplied by the tool.")
    valid = 0
    invalid = 0
    for row in rows[:256]:
        if not isinstance(row, dict):
            invalid += 1
            continue
        total = _bytes(row.get("blocks"))
        used = _bytes(row.get("used"))
        free = _bytes(row.get("available"))
        pct = _percentage(row.get("use_percent"))
        if total is None or used is None or free is None or pct is None:
            invalid += 1
            continue
        mount = _label(row.get("mount"))
        fs = _label(row.get("filesystem"))
        inode = inode_by_mount.get(str(row.get("mount")))
        if persian:
            line = f"- {mount} ({fs}): کل {total}، مصرف‌شده {used}، آزاد {free}، مصرف {pct}"
            if inode:
                line += f"، مصرف inode {inode}"
        else:
            line = f"- {mount} ({fs}): total {total}, used {used}, available {free}, used {pct}"
            if inode:
                line += f", inode used {inode}"
        lines.append(line)
        valid += 1
    if valid == 0:
        return (f"داده‌های دیسک {target} قابل‌اعتبارسنجی نبود؛ ظرفیت اعلام نمی‌شود."
                if persian else f"Disk data for {target} failed validation; capacity not reported.")
    if invalid or len(rows) > 256:
        message = f"هشدار: {invalid} ردیف نامعتبر و {max(0, len(rows)-256)} ردیف خارج از سقف نمایش؛ فهرست ناقص است."
        if not persian:
            message = f"Warning: {invalid} invalid rows and {max(0, len(rows)-256)} rows beyond the display limit; inventory incomplete."
        lines.append(message)
    return "\n".join(lines)


def render_vm_services(payload: dict[str, Any], *, persian: bool = True) -> str | None:
    """Display verified systemd observations without hiding policy scope."""
    result = payload.get("result")
    if not isinstance(result, dict):
        return None
    target = _label(result.get("target"))
    source = _label(payload.get("source") or "vm_mcp")
    if result.get("success") is not True:
        error = _label(result.get("error") or "service_inventory_failed")
        return (f"دریافت فهرست سرویس‌های {target} ناموفق بود: {error}" if persian
                else f"Service inventory failed for {target}: {error}")
    rows = result.get("services")
    if not isinstance(rows, list):
        return None
    count = result.get("matching_count")
    count = count if type(count) is int and count >= 0 else len(rows)
    if persian:
        lines = [f"فهرست سرویس‌های systemd سرور {target} (منبع: {source}؛ موارد منطبق: {count})"]
        if result.get("scope_restricted"):
            lines.append("دامنه: فقط سرویس‌های مجاز Allowlist؛ این فهرست تمام سرویس‌های میزبان نیست.")
        lines.append(f"زمان مشاهده: {_label(result['observed_at'])}" if result.get("observed_at")
                     else "زمان مشاهده توسط ابزار ثبت نشده است.")
    else:
        lines = [f"systemd services for {target} (source: {source}; matches: {count})"]
        if result.get("scope_restricted"):
            lines.append("Scope: allowlisted services only; not the entire host inventory.")
        lines.append(f"Observed: {_label(result['observed_at'])}" if result.get("observed_at")
                     else "Observation timestamp not supplied.")
    for item in rows[:500]:
        if isinstance(item, dict):
            lines.append(f"- {_label(item.get('name'))}: {_label(item.get('active_state'))}/{_label(item.get('sub_state'))} — {_label(item.get('description'))}")
    if result.get("truncated") or len(rows) > 500:
        lines.append("هشدار: فهرست ناقص است." if persian else "Warning: inventory truncated.")
    return "\n".join(lines)
