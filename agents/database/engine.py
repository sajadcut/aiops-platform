from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from agents.database.adapters.postgresql import build_postgresql_analysis, normalize_query_fingerprint
from agents.shared.intelligence import sanitize_prompt_value


QUERY_KEYS = {
    "query", "query_text", "sql", "statement", "current_query", "sample_query",
    "query_sample", "full_query", "command_text",
}
PARAMETER_KEYS = {
    "parameters", "params", "binds", "bind_parameters", "query_parameters",
    "arguments", "literal_parameters",
}


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _eid(item: Mapping[str, Any], index: int) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _parse_time(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _timestamp(item: Mapping[str, Any]) -> Optional[datetime]:
    raw = _raw(item)
    for value in (
        item.get("observed_at"), item.get("timestamp"), item.get("created_at"),
        raw.get("timestamp"), raw.get("@timestamp"),
    ):
        parsed = _parse_time(value)
        if parsed:
            return parsed
    return None


def _number(value: Any) -> Optional[float]:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            value = value.strip().rstrip("%").replace(",", "")
        return float(value)
    except (TypeError, ValueError):
        return None


def _metric(item: Mapping[str, Any]) -> Tuple[str, Optional[float]]:
    raw = _raw(item)
    name = item.get("name") or item.get("metric") or raw.get("name") or raw.get("metric") or raw.get("item_key") or ""
    value = item.get("value") if item.get("value") is not None else raw.get("value")
    return str(name).lower(), _number(value)


def _pick_number(item: Mapping[str, Any], *keys: str) -> Optional[float]:
    raw = _raw(item)
    for source in (item, raw):
        for key in keys:
            value = _number(source.get(key))
            if value is not None:
                return value
    return None


def _incident_start(context: Mapping[str, Any]) -> Optional[datetime]:
    sources = [context]
    summary = context.get("summary") if isinstance(context.get("summary"), Mapping) else None
    if summary:
        sources.append(summary)
    for source in sources:
        for key in ("incident_start", "started_at", "start_time", "created_at"):
            parsed = _parse_time(source.get(key))
            if parsed:
                return parsed
    return None


def _baseline_delta(item: Mapping[str, Any], current: Optional[float] = None) -> Optional[Dict[str, Any]]:
    raw = _raw(item)
    if current is None:
        _, current = _metric(item)
    if current is None:
        current = _pick_number(item, "current", "current_value", "incident_value")
    baseline = None
    for key in (
        "baseline", "baseline_value", "historical", "historical_value", "normal",
        "previous", "previous_value", "pre_incident", "pre_incident_value",
    ):
        baseline = _number(raw.get(key))
        if baseline is not None:
            break
    if baseline is None:
        baseline = _number(item.get("baseline"))
    if current is None or baseline is None:
        return None
    absolute = current - baseline
    relative = None if baseline == 0 else absolute / abs(baseline)
    return {
        "current": current,
        "baseline": baseline,
        "absolute_delta": round(absolute, 6),
        "relative_delta": None if relative is None else round(relative, 4),
    }


def _metric_matches(name: str, aliases: Sequence[str]) -> bool:
    return any(alias in name for alias in aliases)


METRIC_ALIASES: Dict[str, Tuple[str, ...]] = {
    "connections": ("connection_count", "connections_current", "active_connections", "db_connections", "numbackends"),
    "connection_utilization": ("connection_utilization", "connections_ratio", "active_connections_ratio", "connection_usage"),
    "max_connections": ("max_connections", "connection_limit"),
    "pool_utilization": ("pool_utilization", "pool_in_use_ratio", "pool_usage"),
    "pool_waiters": ("pool_waiters", "pool_pending", "connection_waiters", "pool_queue"),
    "rejected_connections": ("rejected_connections", "connection_rejections", "connection_errors", "reserved_slots"),
    "query_latency": ("query_latency", "query_duration", "statement_latency", "mean_exec_time", "avg_query_time"),
    "throughput": ("queries_per_second", "qps", "transactions_per_second", "tps", "throughput"),
    "error_rate": ("db_error_rate", "query_error_rate", "database_errors", "errors_per_second"),
    "long_queries": ("long_running_queries", "long_queries", "slow_queries"),
    "lock_waits": ("lock_waits", "lock_wait_count", "blocked_queries", "blocked_sessions"),
    "deadlocks": ("deadlocks", "deadlock_count"),
    "waits": ("wait_event_count", "wait_count", "db_waits"),
    "transaction_duration": ("transaction_duration", "xact_duration", "transaction_age"),
    "replication_lag": ("replication_lag", "replay_lag", "replica_lag", "standby_lag"),
    "storage_latency": ("storage_latency", "disk_await", "disk_latency", "io_latency"),
    "cpu": ("db_cpu", "database_cpu", "cpu_utilization", "cpu_usage"),
    "memory": ("db_memory", "database_memory", "memory_utilization", "memory_usage"),
    "cache_hit": ("cache_hit", "buffer_cache_hit", "buffer_hit_ratio"),
    "checkpoint": ("checkpoint", "checkpoints_req", "checkpoint_write"),
    "wal": ("wal_bytes", "wal_rate", "wal_write", "wal_sync"),
    "disk_capacity": ("disk_usage", "disk_capacity", "filesystem_usage", "volume_usage"),
}


def _feature_rows(items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    rows: Dict[str, List[Dict[str, Any]]] = {key: [] for key in METRIC_ALIASES}
    for index, item in enumerate(items):
        name, value = _metric(item)
        if value is None or not name:
            continue
        for feature, aliases in METRIC_ALIASES.items():
            if not _metric_matches(name, aliases):
                continue
            delta = _baseline_delta(item, value)
            rows[feature].append({
                "evidence_id": _eid(item, index),
                "metric": name,
                "value": value,
                "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
                **({"baseline": delta["baseline"], "absolute_delta": delta["absolute_delta"], "relative_delta": delta["relative_delta"]} if delta else {}),
            })
    return rows


def _latest(rows: Mapping[str, List[Dict[str, Any]]], feature: str) -> Optional[float]:
    values = rows.get(feature) or []
    if not values:
        return None
    return _number(values[-1].get("value"))


def _connection_analysis(rows: Mapping[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    count = _latest(rows, "connections")
    ratio = _latest(rows, "connection_utilization")
    max_connections = _latest(rows, "max_connections")
    if ratio is None and count is not None and max_connections not in (None, 0):
        ratio = count / float(max_connections)
    pool = _latest(rows, "pool_utilization")
    waiters = _latest(rows, "pool_waiters")
    rejected = _latest(rows, "rejected_connections")
    state = "unknown"
    if rejected and rejected > 0:
        state = "rejecting_connections"
    elif ratio is not None and ratio >= 0.95:
        state = "connection_capacity_exhausted"
    elif waiters and waiters > 0 and pool is not None and pool >= 0.95:
        state = "pool_exhausted"
    elif ratio is not None and ratio >= 0.8:
        state = "busy"
    elif ratio is not None:
        state = "within_capacity"
    evidence_ids = []
    for key in ("connections", "connection_utilization", "max_connections", "pool_utilization", "pool_waiters", "rejected_connections"):
        evidence_ids.extend(str(row["evidence_id"]) for row in rows.get(key, []) if row.get("evidence_id"))
    return {
        "state": state,
        "connection_count": count,
        "max_connections": max_connections,
        "connection_utilization": round(ratio, 4) if ratio is not None else None,
        "pool_utilization": pool,
        "pool_waiters": waiters,
        "rejected_connections": rejected,
        "evidence_ids": list(dict.fromkeys(evidence_ids))[:20],
    }


def _common_query_rows(items: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        raw = _raw(item)
        supplied = raw.get("query_fingerprint") or raw.get("normalized_query") or raw.get("fingerprint")
        query = raw.get("query") or raw.get("query_text") or raw.get("statement") or raw.get("sql")
        query_id = raw.get("queryid") or raw.get("query_id") or raw.get("fingerprint_id")
        fingerprint = normalize_query_fingerprint(supplied or query)
        if not fingerprint and query_id in (None, ""):
            continue
        latency = _pick_number(item, "query_latency_ms", "latency_ms", "mean_exec_time_ms", "mean_time_ms", "duration_ms")
        baseline = _pick_number(item, "baseline_latency_ms", "baseline_mean_exec_time_ms", "historical_latency_ms")
        relative = None
        if latency is not None and baseline not in (None, 0):
            relative = (latency - float(baseline)) / abs(float(baseline))
        result.append({
            "evidence_id": _eid(item, index),
            "query_id": str(query_id)[:128] if query_id not in (None, "") else None,
            "query_fingerprint": fingerprint,
            "latency_ms": latency,
            "baseline_latency_ms": baseline,
            "relative_latency_delta": round(relative, 4) if relative is not None else None,
            "calls": _pick_number(item, "calls", "executions", "query_count"),
            "throughput": _pick_number(item, "qps", "queries_per_second", "throughput"),
        })
    result.sort(
        key=lambda row: (
            abs(float(row.get("relative_latency_delta") or 0)),
            float(row.get("latency_ms") or 0),
            float(row.get("calls") or 0),
        ),
        reverse=True,
    )
    return result[:20]


def _wait_rows(items: Sequence[Mapping[str, Any]], postgres: Mapping[str, Any]) -> List[Dict[str, Any]]:
    waits: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        raw = _raw(item)
        event = raw.get("wait_event") or raw.get("wait_name") or raw.get("wait_type")
        if event in (None, ""):
            continue
        waits.append({
            "evidence_id": _eid(item, index),
            "wait_event": str(event)[:180],
            "wait_event_type": str(raw.get("wait_event_type") or raw.get("category") or "")[:120] or None,
            "count": _pick_number(item, "wait_count", "count"),
            "duration_ms": _pick_number(item, "wait_duration_ms", "duration_ms", "total_wait_ms"),
        })
    for row in postgres.get("top_wait_events") or []:
        if isinstance(row, Mapping):
            waits.append(dict(row))
    waits.sort(key=lambda row: (float(row.get("duration_ms") or 0), float(row.get("count") or 0)), reverse=True)
    dedup: List[Dict[str, Any]] = []
    seen = set()
    for row in waits:
        key = (row.get("evidence_id"), row.get("wait_event"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(row)
    return dedup[:12]


def _temporal_deltas(items: Sequence[Mapping[str, Any]], query_rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    deltas: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        name, value = _metric(item)
        delta = _baseline_delta(item, value)
        if name and delta:
            deltas.append({"kind": "metric", "name": name, "evidence_id": _eid(item, index), **delta})
    for row in query_rows:
        relative = _number(row.get("relative_latency_delta"))
        if relative is None:
            continue
        deltas.append({
            "kind": "query_fingerprint",
            "name": row.get("query_fingerprint") or row.get("query_id"),
            "evidence_id": row.get("evidence_id"),
            "current": row.get("latency_ms") or row.get("mean_exec_time_ms"),
            "baseline": row.get("baseline_latency_ms") or row.get("baseline_mean_exec_time_ms"),
            "relative_delta": relative,
        })
    deltas.sort(key=lambda row: abs(float(row.get("relative_delta") or 0)), reverse=True)
    return deltas[:12]


def _event_analysis(items: Sequence[Mapping[str, Any]], incident_start: Optional[datetime]) -> Dict[str, Any]:
    restart_failover: List[Dict[str, Any]] = []
    db_errors: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        raw = _raw(item)
        message = str(item.get("message") or raw.get("message") or raw.get("error") or "")[:500]
        diagnostic = str(raw.get("diagnostic") or "").lower()
        lowered = message.lower()
        stamp = _timestamp(item)
        if diagnostic in {"restart", "database_restart", "failover", "promotion", "switchover"} or any(
            token in lowered for token in ("database system is ready to accept connections", "promoted to primary", "failover", "database restart")
        ):
            restart_failover.append({
                "evidence_id": _eid(item, index),
                "timestamp": stamp.isoformat() if stamp else None,
                "event": diagnostic or "restart_or_failover",
                "incident_offset_seconds": round((stamp - incident_start).total_seconds(), 3) if stamp and incident_start else None,
            })
        if str(item.get("type", "")).lower() == "log" and (
            any(token in lowered for token in ("fatal", "error", "deadlock", "could not connect", "too many connections", "reserved connection slots"))
            or str(item.get("severity") or "").lower() in {"error", "critical", "fatal"}
        ):
            db_errors.append({
                "evidence_id": _eid(item, index),
                "timestamp": stamp.isoformat() if stamp else None,
                "error_class": next((token for token in ("deadlock", "too many connections", "reserved connection slots", "could not connect", "fatal", "error") if token in lowered), "database_error"),
            })
    return {"restart_failover_events": restart_failover[:20], "database_error_logs": db_errors[:30]}


def _resource_analysis(rows: Mapping[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    cpu = _latest(rows, "cpu")
    memory = _latest(rows, "memory")
    storage = _latest(rows, "storage_latency")
    disk = _latest(rows, "disk_capacity")
    cache_hit = _latest(rows, "cache_hit")
    checkpoint = _latest(rows, "checkpoint")
    wal = _latest(rows, "wal")
    return {
        "cpu_utilization": cpu,
        "memory_utilization": memory,
        "storage_latency_ms": storage,
        "disk_capacity_percent": disk,
        "cache_hit_ratio": cache_hit,
        "checkpoint_signal": checkpoint,
        "wal_signal": wal,
        "cpu_saturated": cpu is not None and cpu >= 90,
        "memory_saturated": memory is not None and memory >= 90,
        "storage_slow": storage is not None and storage >= 20,
        "capacity_exhausted": disk is not None and disk >= 95,
    }


def _replication_analysis(rows: Mapping[str, List[Dict[str, Any]]], postgres: Mapping[str, Any]) -> Dict[str, Any]:
    lag = _latest(rows, "replication_lag")
    vendor_rows = [row for row in (postgres.get("replication") or []) if isinstance(row, Mapping)]
    vendor_lags = [_number(row.get("lag_seconds")) for row in vendor_rows]
    vendor_lags = [value for value in vendor_lags if value is not None]
    if vendor_lags:
        lag = max(([lag] if lag is not None else []) + vendor_lags)
    unhealthy_states = [
        row for row in vendor_rows
        if str(row.get("state") or "").lower() in {"down", "failed", "disconnected", "catchup", "stopped"}
    ]
    return {
        "lag_seconds": lag,
        "unhealthy_state_evidence": unhealthy_states[:10],
        "degraded": bool((lag is not None and lag >= 10) or unhealthy_states),
    }


def _cause_candidates(
    items: Sequence[Mapping[str, Any]],
    rows: Mapping[str, List[Dict[str, Any]]],
    connection: Mapping[str, Any],
    queries: Sequence[Mapping[str, Any]],
    waits: Sequence[Mapping[str, Any]],
    resources: Mapping[str, Any],
    replication: Mapping[str, Any],
    postgres: Mapping[str, Any],
    events: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    def add(code: str, evidence_ids: Iterable[Any], *, handoff: Optional[str] = None, basis: str) -> None:
        ids = [str(value) for value in evidence_ids if value not in (None, "")]
        candidates.append({
            "code": code,
            "evidence_ids": list(dict.fromkeys(ids))[:20],
            "handoff": handoff,
            "basis": basis,
            "root_cause_status": "candidate_requires_falsification",
        })

    if connection.get("state") in {"connection_capacity_exhausted", "rejecting_connections", "pool_exhausted"}:
        add("connection_capacity_exhaustion", connection.get("evidence_ids") or [], basis="connection/pool utilization or rejection evidence")

    storm_ids: List[str] = []
    for row in rows.get("connections", []) + rows.get("connection_utilization", []):
        relative = _number(row.get("relative_delta"))
        if relative is not None and relative >= 0.5:
            storm_ids.append(str(row.get("evidence_id")))
    app_ids: List[str] = []
    for index, item in enumerate(items):
        raw = _raw(item)
        text = " ".join(str(value or "") for value in (
            item.get("name"), item.get("message"), raw.get("application_name"), raw.get("client_application"),
            raw.get("diagnostic"), raw.get("source_component"),
        )).lower()
        if any(token in text for token in ("pool_wait", "pool waiter", "connection storm", "client connections", "app connection")):
            app_ids.append(_eid(item, index))
    if storm_ids and app_ids:
        add("application_connection_storm", storm_ids + app_ids, handoff="application", basis="connection delta plus client/application evidence")

    slow = [
        row for row in queries
        if (_number(row.get("relative_latency_delta")) or 0) >= 0.5
        or (_number(row.get("latency_ms")) or _number(row.get("mean_exec_time_ms")) or 0) >= 1000
    ]
    if slow:
        add("slow_query", [row.get("evidence_id") for row in slow[:5]], basis="query fingerprint latency exceeds baseline/absolute threshold")

    lock_wait_ids = [str(row.get("evidence_id")) for row in waits if "lock" in str(row.get("wait_event_type") or row.get("wait_event") or "").lower()]
    lock_wait_ids.extend(str(row.get("evidence_id")) for row in rows.get("lock_waits", []) if (_number(row.get("value")) or 0) > 0)
    deadlock_ids = list(postgres.get("deadlock_evidence_ids") or [])
    deadlock_ids.extend(str(row.get("evidence_id")) for row in rows.get("deadlocks", []) if (_number(row.get("value")) or 0) > 0)
    if deadlock_ids:
        add("deadlock", deadlock_ids, basis="deadlock counter/log evidence")
    if lock_wait_ids:
        add("lock_contention", lock_wait_ids, basis="lock wait events or blocked-session evidence")

    if resources.get("cpu_saturated"):
        add("database_cpu_saturation", [row.get("evidence_id") for row in rows.get("cpu", [])], handoff="infrastructure", basis="database/host CPU saturation evidence")
    if resources.get("storage_slow"):
        add("storage_induced_latency", [row.get("evidence_id") for row in rows.get("storage_latency", [])], handoff="storage", basis="storage latency elevated")
    if resources.get("capacity_exhausted"):
        add("capacity_exhaustion", [row.get("evidence_id") for row in rows.get("disk_capacity", [])], handoff="storage", basis="database filesystem/volume near capacity")
    if replication.get("degraded"):
        ids = [row.get("evidence_id") for row in postgres.get("replication", []) if isinstance(row, Mapping)]
        ids += [row.get("evidence_id") for row in rows.get("replication_lag", [])]
        add("replication_issue", ids, handoff="recovery", basis="replication lag/state degraded")

    network_ids: List[str] = []
    dependency_ids: List[str] = []
    for index, item in enumerate(items):
        raw = _raw(item)
        text = " ".join(str(value or "") for value in (
            item.get("name"), item.get("message"), raw.get("diagnostic"), raw.get("error"),
            raw.get("dependency"), raw.get("downstream"), raw.get("network_state"),
        )).lower()
        if any(token in text for token in ("connection refused", "network unreachable", "dns", "tcp timeout", "connection reset")):
            network_ids.append(_eid(item, index))
        if any(token in text for token in ("downstream dependency", "external dependency", "remote service", "foreign data wrapper")):
            dependency_ids.append(_eid(item, index))
    if network_ids:
        add("network_connectivity", network_ids, handoff="network", basis="explicit network/TCP/DNS connectivity evidence")
    if dependency_ids:
        add("downstream_dependency", dependency_ids, handoff="dependency", basis="explicit downstream dependency evidence")

    throughput = _latest(rows, "throughput")
    errors = _latest(rows, "error_rate")
    if (
        throughput is not None and throughput > 0
        and connection.get("state") in {"busy", "within_capacity"}
        and not candidates
        and not resources.get("cpu_saturated")
        and not resources.get("storage_slow")
        and not replication.get("degraded")
        and not events.get("database_error_logs")
        and (errors is None or errors == 0)
    ):
        ids = [row.get("evidence_id") for row in rows.get("throughput", []) + rows.get("connection_utilization", [])]
        add("healthy_busy_database", ids, basis="high activity remains within capacity with no corroborating error/saturation evidence")

    return candidates[:16]


def build_database_reliability_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    ctx = context if isinstance(context, Mapping) else {}
    incident_start = _incident_start(ctx)
    feature_rows = _feature_rows(items)
    postgres = build_postgresql_analysis(items)
    common_queries = _common_query_rows(items)
    vendor_queries = [row for row in (postgres.get("pg_stat_statements") or []) if isinstance(row, Mapping)]
    query_map: Dict[Tuple[Any, Any], Dict[str, Any]] = {}
    for row in common_queries + vendor_queries:
        key = (row.get("evidence_id"), row.get("query_id") or row.get("query_fingerprint"))
        query_map[key] = dict(row)
    queries = list(query_map.values())
    queries.sort(
        key=lambda row: (
            abs(float(row.get("relative_latency_delta") or 0)),
            float(row.get("latency_ms") or row.get("mean_exec_time_ms") or 0),
            float(row.get("calls") or 0),
        ),
        reverse=True,
    )
    waits = _wait_rows(items, postgres)
    deltas = _temporal_deltas(items, queries)
    connection = _connection_analysis(feature_rows)
    resources = _resource_analysis(feature_rows)
    replication = _replication_analysis(feature_rows, postgres)
    events = _event_analysis(items, incident_start)
    causes = _cause_candidates(items, feature_rows, connection, queries, waits, resources, replication, postgres, events)

    handoffs: List[str] = []
    for row in causes:
        target = str(row.get("handoff") or "")
        if target and target != "database" and target not in handoffs:
            handoffs.append(target)

    gaps: List[Dict[str, Any]] = []
    if connection.get("connection_utilization") is None and connection.get("connection_count") is None:
        gaps.append({"evidence": "connection count/utilization and configured capacity", "information_gain": 0.97})
    if not queries:
        gaps.append({"evidence": "normalized query fingerprints with incident and historical latency/throughput", "information_gain": 0.94})
    if not waits and not postgres.get("locks"):
        gaps.append({"evidence": "lock waits/deadlocks/wait events", "information_gain": 0.91})
    if replication.get("lag_seconds") is None and not postgres.get("replication"):
        gaps.append({"evidence": "replication role/state/lag", "information_gain": 0.78})
    if resources.get("storage_latency_ms") is None:
        gaps.append({"evidence": "database storage latency and capacity", "information_gain": 0.84})
    if resources.get("cpu_utilization") is None:
        gaps.append({"evidence": "database/host CPU saturation", "information_gain": 0.81})
    if not events.get("database_error_logs"):
        gaps.append({"evidence": "database error logs in the incident window", "information_gain": 0.76})
    gaps.sort(key=lambda row: float(row["information_gain"]), reverse=True)

    return {
        "policy": "database alerts are symptoms; root cause requires cross-layer evidence and falsification",
        "query_text_policy": "raw SQL/literal parameters must not enter prompts or logs; use normalized fingerprints/query IDs",
        "service": service_name,
        "incident_start": incident_start.isoformat() if incident_start else None,
        "connection_analysis": connection,
        "query_analysis": {
            "top_query_fingerprints": queries[:12],
            "long_running_query_count": _latest(feature_rows, "long_queries"),
            "query_latency_ms": _latest(feature_rows, "query_latency"),
            "throughput": _latest(feature_rows, "throughput"),
            "error_rate": _latest(feature_rows, "error_rate"),
        },
        "contention_analysis": {
            "top_waits": waits,
            "lock_wait_count": _latest(feature_rows, "lock_waits"),
            "deadlock_count": _latest(feature_rows, "deadlocks"),
            "transaction_duration_ms": _latest(feature_rows, "transaction_duration"),
        },
        "replication_analysis": replication,
        "resource_analysis": resources,
        "event_analysis": events,
        "postgresql": postgres,
        "biggest_temporal_deltas": deltas,
        "cause_candidates": causes,
        "handoff_candidates": handoffs[:8],
        "evidence_gaps": gaps[:8],
        "next_best_evidence": gaps[:6],
        "analysis_stages": [
            "connections", "queries", "locks_waits_transactions", "replication",
            "cpu_memory_cache", "wal_checkpoint", "storage_capacity", "events_logs",
            "incident_vs_baseline", "cross_layer_cause_falsification",
        ],
    }


def _sanitize_db_mapping(value: Any, depth: int = 0) -> Any:
    if depth >= 5:
        return "[bounded]"
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        fingerprint_added = False
        for key, current in list(value.items())[:40]:
            normalized = str(key).strip().lower()
            if normalized in PARAMETER_KEYS:
                result[str(key)] = "[REDACTED]"
                continue
            if normalized in QUERY_KEYS:
                fingerprint = normalize_query_fingerprint(current)
                if fingerprint and not fingerprint_added:
                    result["query_fingerprint"] = fingerprint
                    fingerprint_added = True
                continue
            result[str(key)] = _sanitize_db_mapping(current, depth + 1)
        return sanitize_prompt_value(result)
    if isinstance(value, list):
        return [_sanitize_db_mapping(item, depth + 1) for item in value[:10]]
    if isinstance(value, tuple):
        return [_sanitize_db_mapping(item, depth + 1) for item in list(value)[:10]]
    return sanitize_prompt_value(value)


def database_prompt_evidence_projection(evidence: Iterable[Mapping[str, Any]], limit: int = 40) -> List[Dict[str, Any]]:
    projected: List[Dict[str, Any]] = []
    for item in list(evidence)[:limit]:
        if not isinstance(item, Mapping):
            continue
        raw = _raw(item)
        message = item.get("message")
        message_safe: Any = message
        if isinstance(message, str):
            lowered = message.lower()
            if any(token in lowered for token in ("select ", "insert ", "update ", "delete ", "with ")):
                fingerprint = normalize_query_fingerprint(message)
                message_safe = f"[SQL fingerprint] {fingerprint}" if fingerprint else "[SQL redacted]"
        projected.append(_sanitize_db_mapping({
            "id": item.get("evidence_id") or item.get("id") or item.get("reference"),
            "type": item.get("type"),
            "source": item.get("source"),
            "timestamp": item.get("observed_at") or item.get("timestamp") or item.get("created_at"),
            "name": item.get("name"),
            "value": item.get("value"),
            "message": message_safe,
            "severity": item.get("severity"),
            "raw_data": raw,
        }))
    return projected
