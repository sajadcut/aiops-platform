"""Verified Elasticsearch evidence for one Incident, never journal/MCP guessing."""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from domain.contracts.redaction import redact_text
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient


def is_elastic_question(message: str) -> bool:
    import re
    return re.search(r"الاستیک|الستیک|الستیک|الاسـتیک|elastic(?:search)?|kibana|\belk\b",
                     message or "", re.I) is not None


def wants_live_elastic(message: str) -> bool:
    import re
    return bool(re.search(
        r"\bmcp\b|استعلام|کوئری|جستجو|جست‌وجو|برو\s*ببین|الان|زنده|"
        r"دوباره|مجدد|چک\s*کن|بررسی\s*کن|"
        r"\b(?:query|search|recheck|check|fetch|live|now)\b", message or "", re.I,
    ))


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError):
            pass
    return None


def stored_elastic_observations(evidence: list[dict], *, service: str) -> dict:
    """Only Elasticsearch-tagged saved evidence may establish recorded ELK use.

    Systemd service_logs, Zabbix and inferred LLM narrative are never merged
    into an Elasticsearch finding.
    """
    rows = []
    for item in evidence[-700:]:
        if not isinstance(item, dict) or str(item.get("source") or "").lower() != "elasticsearch":
            continue
        raw = item.get("raw_data") or {}
        if not isinstance(raw, dict):
            continue
        named = str(raw.get("service") or raw.get("service.name") or "").strip().lower()
        if named and named != str(service or "").strip().lower():
            continue
        ref = str(item.get("reference") or item.get("id") or "")[:170]
        if raw.get("status") in {"queried", "unavailable", "error", "skipped"}:
            count = raw.get("result_count")
            rows.append({
                "status": raw["status"],
                "count": count if type(count) is int and 0 <= count <= 100000 else None,
                "source_ref": ref, "observed_at": _iso(item.get("created_at") or item.get("timestamp")),
            })
        elif "message" in raw:
            rows.append({
                "status": "log_record", "count": None,
                "source_ref": ref, "observed_at": _iso(item.get("created_at") or item.get("timestamp")),
            })
    observations = [r for r in rows if r["status"] != "log_record"]
    last = observations[-1] if observations else None
    return {
        "source": "elasticsearch",
        "status": last["status"] if last else "not_recorded",
        "recorded_count": last["count"] if last else None,
        "sampled_log_evidence_count": sum(r["status"] == "log_record" for r in rows),
        "evidence_refs": list(dict.fromkeys(r["source_ref"] for r in rows if r["source_ref"]))[-8:],
        "query_time": last["observed_at"] if last else None,
        "is_live": False,
    }


async def elastic_live_read(
    service: str, *, incident_started_at: Any = None,
    connector: Any = None, clock: datetime | None = None,
) -> dict:
    """Fixed service-scoped Agent Builder ES|QL, capped six-hour lookback."""
    now = (clock or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = now - timedelta(hours=6)
    if incident_started_at:
        if isinstance(incident_started_at, datetime):
            candidate = incident_started_at
        else:
            try:
                candidate = datetime.fromisoformat(
                    str(incident_started_at).replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                candidate = None
        if candidate:
            if candidate.tzinfo is None:
                candidate = candidate.replace(tzinfo=timezone.utc)
            start = max(start, min(candidate.astimezone(timezone.utc), now))
    if not str(service or "").strip():
        return {"source": "elasticsearch", "success": False, "status": "service_unknown",
                "is_live": True, "results": []}
    try:
        client = connector or ElasticsearchMCPClient()
        logs = await asyncio.wait_for(
            client.get_logs(service, start, now, limit=40),
            timeout=24.0,
        )
    except Exception as exc:
        return {"source": "elasticsearch", "success": False,
                "status": "elastic_mcp_unavailable",
                "error_type": type(exc).__name__[:50], "is_live": True,
                "results": [], "searched_service": str(service)[:90],
                "from": start.isoformat(), "until": now.isoformat()}
    samples = []
    levels = Counter()
    for log in logs[:40]:
        level = str(getattr(log, "level", "unknown") or "unknown").lower()[:20]
        if level not in {"error", "fatal", "critical", "warn", "warning", "info", "debug", "trace"}:
            level = "unknown"
        levels[level] += 1
        if len(samples) < 8:
            message = redact_text(str(getattr(log, "message", "") or ""))[:280]
            samples.append({
                "time": _iso(getattr(log, "timestamp", None)),
                "level": level, "message": message,
            })
    return {
        "source": "elasticsearch", "success": True,
        "status": "queried" if logs else "empty",
        "is_live": True, "searched_service": str(service)[:90],
        "from": start.isoformat(), "until": now.isoformat(),
        "returned_count": min(len(logs), 40), "limit": 40,
        "levels": dict(levels), "results": samples,
        "results_are_sampled": True,
        "absence_of_errors_proven": False,
    }


def elastic_answer(observation: dict, *, persian: bool = True) -> str:
    """Never infer that missing matches prove the absence of other errors."""
    live = observation.get("is_live") is True
    status = str(observation.get("status") or "unknown")
    if live:
        if observation.get("success") is not True:
            return (
                "استعلام زندهٔ Elasticsearch MCP ناموفق بود ("+status+
                "). هیچ نتیجهٔ لاگ Elastic تأیید نشده است. این خطا ربطی به "
                "دسترسی VM MCP ندارد."
                if persian else
                "Live Elasticsearch MCP query failed ("+status+
                "). No Elasticsearch log result was verified; this is separate from VM MCP.")
        title = ("استعلام زندهٔ Elasticsearch MCP انجام شد. "
                 if persian else "Live Elasticsearch MCP query completed. ")
        title += (f"سرویس: {observation.get('searched_service')}; "
                  f"بازه: {observation.get('from')} تا {observation.get('until')}; "
                  f"تعداد رکوردهای برگشتی: {observation.get('returned_count')} (حداکثر ۴۰).")
        summary = ", ".join(f"{key}={value}" for key, value in (
            observation.get("levels") or {}
        ).items())
        if summary:
            title += "\n" + ("سطوح لاگ: " if persian else "Log levels: ") + summary
        for row in (observation.get("results") or [])[:6]:
            title += "\n• " + str(row.get("time") or "?") + " [" + str(row.get("level") or "?") + "] " + str(row.get("message") or "")
        title += (
            "\nاین نتیجه نمونهٔ محدود است؛ عدم مشاهدهٔ 401/403 یا خطای دیگر به معنای رد قطعی آن نیست."
            if persian else
            "\nThese are bounded results; no sampled 401/403 does not rule out authentication errors."
        )
        return title
    if status == "queried":
        count = observation.get("recorded_count")
        if persian:
            return ("بر اساس شواهد ثبت‌شده، Elasticsearch قبلاً استعلام شده است؛ "
                    f"تعداد نتایج گزارش‌شده: {count if count is not None else 'نامشخص'}. "
                    "محتوای کامل نتیجه در این خلاصه موجود نیست؛ برای بررسی دقیق، "
                    "استعلام زندهٔ Elasticsearch MCP درخواست کنید.")
        return "Saved evidence confirms an Elasticsearch query; reported result count: " + str(count) + ". Raw query findings are not established by this summary."
    if status in {"unavailable", "error", "skipped"}:
        return (
            f"در تحلیل ثبت‌شده، وضعیت Elasticsearch برابر {status} بوده؛ نتیجهٔ معتبری برای استنتاج دربارهٔ لاگ‌ها وجود ندارد."
            if persian else f"Saved Elasticsearch collection status was {status}; there are no verified logs to summarize."
        )
    return (
        "شاهد مستقلی از نتیجهٔ استعلام Elasticsearch در این رخداد ثبت نشده است؛ "
        "لاگ‌های systemd با لاگ‌های Elasticsearch یکسان نیستند."
        if persian else
        "No verified Elasticsearch query result is recorded for this incident; systemd logs are not Elasticsearch logs."
    )
