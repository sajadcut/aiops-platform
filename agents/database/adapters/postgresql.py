from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional


_SQL_LITERAL_RE = re.compile(
    r"""(?xs)
    (?:E?'(?:''|[^'])*')
    |(?:"(?:[^"]|"")*")
    |(?:\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b)
    |(?:\b\d+(?:\.\d+)?\b)
    """
)
_DOLLAR_QUOTE_RE = re.compile(r"(?s)\$\$.*?\$\$|\$([A-Za-z_][A-Za-z0-9_]*)\$.*?\$\1\$")
_PARAM_RE = re.compile(r"\$\d+")
_WS_RE = re.compile(r"\s+")


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _eid(item: Mapping[str, Any], index: int) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _number(value: Any) -> Optional[float]:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            value = value.strip().rstrip("%").replace(",", "")
        return float(value)
    except (TypeError, ValueError):
        return None


def _pick_number(item: Mapping[str, Any], *keys: str) -> Optional[float]:
    raw = _raw(item)
    for source in (item, raw):
        for key in keys:
            value = _number(source.get(key))
            if value is not None:
                return value
    return None


def _pick_text(item: Mapping[str, Any], *keys: str) -> Optional[str]:
    raw = _raw(item)
    for source in (item, raw):
        for key in keys:
            value = source.get(key)
            if value not in (None, "") and not isinstance(value, (Mapping, list, tuple)):
                return str(value)[:400]
    return None


def normalize_query_fingerprint(query: Any) -> Optional[str]:
    """Return a bounded SQL fingerprint without literal values."""
    if query in (None, ""):
        return None
    text = str(query)
    text = _DOLLAR_QUOTE_RE.sub("?", text)
    text = _SQL_LITERAL_RE.sub("?", text)
    text = _PARAM_RE.sub("$?", text)
    text = _WS_RE.sub(" ", text).strip().lower()
    return text[:360] or None


def _looks_postgresql(item: Mapping[str, Any]) -> bool:
    raw = _raw(item)
    values = " ".join(
        str(value or "")
        for value in (
            item.get("source"), item.get("name"), raw.get("vendor"), raw.get("database"),
            raw.get("db_system"), raw.get("diagnostic"), raw.get("view"),
        )
    ).lower()
    return any(token in values for token in ("postgres", "postgresql", "pg_stat", "pg_locks", "wal", "autovacuum"))


def _query_row(item: Mapping[str, Any], index: int) -> Optional[Dict[str, Any]]:
    raw = _raw(item)
    diagnostic = str(raw.get("diagnostic") or raw.get("view") or "").lower()
    query_id = raw.get("queryid") or raw.get("query_id") or raw.get("fingerprint_id")
    supplied_fingerprint = raw.get("query_fingerprint") or raw.get("normalized_query") or raw.get("fingerprint")
    raw_query = raw.get("query") or raw.get("query_text") or raw.get("statement") or raw.get("sql")
    relevant = (
        "pg_stat_statements" in diagnostic
        or str(item.get("type", "")).lower() in {"query_stats", "query_stat"}
        or query_id not in (None, "")
        or supplied_fingerprint not in (None, "")
        or raw_query not in (None, "")
    )
    if not relevant:
        return None
    fingerprint = normalize_query_fingerprint(supplied_fingerprint or raw_query)
    if not fingerprint and query_id in (None, ""):
        return None
    mean_ms = _pick_number(item, "mean_exec_time_ms", "mean_time_ms", "avg_latency_ms", "query_latency_ms", "latency_ms")
    baseline_ms = _pick_number(item, "baseline_mean_exec_time_ms", "baseline_latency_ms", "historical_latency_ms", "baseline")
    calls = _pick_number(item, "calls", "executions", "query_count")
    total_ms = _pick_number(item, "total_exec_time_ms", "total_time_ms")
    relative_delta = None
    if mean_ms is not None and baseline_ms not in (None, 0):
        relative_delta = (mean_ms - float(baseline_ms)) / abs(float(baseline_ms))
    return {
        "evidence_id": _eid(item, index),
        "query_id": str(query_id)[:128] if query_id not in (None, "") else None,
        "query_fingerprint": fingerprint,
        "calls": calls,
        "mean_exec_time_ms": mean_ms,
        "total_exec_time_ms": total_ms,
        "baseline_mean_exec_time_ms": baseline_ms,
        "relative_latency_delta": round(relative_delta, 4) if relative_delta is not None else None,
        "rows": _pick_number(item, "rows", "rows_processed"),
    }


def build_postgresql_analysis(evidence: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping) and _looks_postgresql(item)]
    activity: List[Dict[str, Any]] = []
    locks: List[Dict[str, Any]] = []
    waits: List[Dict[str, Any]] = []
    replication: List[Dict[str, Any]] = []
    vacuum: List[Dict[str, Any]] = []
    wal_checkpoint: List[Dict[str, Any]] = []
    queries: List[Dict[str, Any]] = []
    deadlock_ids: List[str] = []

    for index, item in enumerate(items):
        raw = _raw(item)
        diagnostic = str(raw.get("diagnostic") or raw.get("view") or "").lower()
        eid = _eid(item, index)
        query = _query_row(item, index)
        if query:
            queries.append(query)

        if "pg_stat_activity" in diagnostic or diagnostic in {"activity", "connection_activity"}:
            activity.append({
                "evidence_id": eid,
                "state": _pick_text(item, "state"),
                "wait_event_type": _pick_text(item, "wait_event_type"),
                "wait_event": _pick_text(item, "wait_event"),
                "application_name": _pick_text(item, "application_name", "client_application"),
                "backend_type": _pick_text(item, "backend_type"),
                "transaction_duration_ms": _pick_number(item, "transaction_duration_ms", "xact_duration_ms"),
                "query_duration_ms": _pick_number(item, "query_duration_ms", "query_age_ms"),
            })

        if "pg_locks" in diagnostic or diagnostic in {"locks", "lock_wait", "lock"}:
            locks.append({
                "evidence_id": eid,
                "lock_type": _pick_text(item, "lock_type", "locktype"),
                "mode": _pick_text(item, "mode"),
                "granted": raw.get("granted"),
                "wait_ms": _pick_number(item, "wait_ms", "lock_wait_ms", "duration_ms"),
            })

        wait_event = _pick_text(item, "wait_event")
        wait_count = _pick_number(item, "wait_count", "count")
        if wait_event or "wait_event" in diagnostic:
            waits.append({
                "evidence_id": eid,
                "wait_event_type": _pick_text(item, "wait_event_type"),
                "wait_event": wait_event or "unknown",
                "count": wait_count,
                "duration_ms": _pick_number(item, "wait_duration_ms", "duration_ms", "total_wait_ms"),
            })

        if "deadlock" in diagnostic or _pick_number(item, "deadlocks", "deadlock_count"):
            deadlock_ids.append(eid)

        if "replication" in diagnostic or any(key in raw for key in ("replication_lag_seconds", "replay_lag_seconds", "write_lag_seconds", "flush_lag_seconds")):
            replication.append({
                "evidence_id": eid,
                "role": _pick_text(item, "role", "replication_role"),
                "state": _pick_text(item, "state", "replication_state"),
                "sync_state": _pick_text(item, "sync_state"),
                "lag_seconds": _pick_number(item, "replication_lag_seconds", "replay_lag_seconds", "write_lag_seconds", "flush_lag_seconds", "lag_seconds"),
            })

        if "vacuum" in diagnostic or "autovacuum" in diagnostic or any(key in raw for key in ("dead_tuples", "n_dead_tup", "autovacuum_age_seconds")):
            vacuum.append({
                "evidence_id": eid,
                "relation": _pick_text(item, "relation", "table", "relname"),
                "dead_tuples": _pick_number(item, "dead_tuples", "n_dead_tup"),
                "live_tuples": _pick_number(item, "live_tuples", "n_live_tup"),
                "autovacuum_age_seconds": _pick_number(item, "autovacuum_age_seconds", "seconds_since_autovacuum"),
                "vacuum_running": raw.get("vacuum_running") if isinstance(raw.get("vacuum_running"), bool) else None,
            })

        if any(token in diagnostic for token in ("wal", "checkpoint")) or any(
            key in raw for key in ("wal_bytes_per_second", "wal_rate_bytes", "checkpoint_write_time_ms", "checkpoints_req", "checkpoints_timed")
        ):
            wal_checkpoint.append({
                "evidence_id": eid,
                "wal_bytes_per_second": _pick_number(item, "wal_bytes_per_second", "wal_rate_bytes", "wal_bytes"),
                "checkpoint_write_time_ms": _pick_number(item, "checkpoint_write_time_ms", "checkpoint_write_ms"),
                "checkpoint_sync_time_ms": _pick_number(item, "checkpoint_sync_time_ms", "checkpoint_sync_ms"),
                "checkpoints_requested": _pick_number(item, "checkpoints_req", "checkpoints_requested"),
                "checkpoints_timed": _pick_number(item, "checkpoints_timed"),
            })

    queries.sort(
        key=lambda row: (
            abs(float(row.get("relative_latency_delta") or 0)),
            float(row.get("total_exec_time_ms") or 0),
            float(row.get("mean_exec_time_ms") or 0),
        ),
        reverse=True,
    )
    waits.sort(key=lambda row: (float(row.get("duration_ms") or 0), float(row.get("count") or 0)), reverse=True)
    return {
        "vendor": "postgresql",
        "evidence_count": len(items),
        "pg_stat_activity": activity[:30],
        "pg_stat_statements": queries[:20],
        "locks": locks[:20],
        "deadlock_evidence_ids": list(dict.fromkeys(deadlock_ids))[:20],
        "top_wait_events": waits[:12],
        "replication": replication[:16],
        "vacuum_autovacuum": vacuum[:16],
        "wal_checkpoint": wal_checkpoint[:16],
        "query_text_policy": "raw SQL and literal parameters are excluded; normalized fingerprints/query IDs only",
    }
