from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SENSITIVE_TOKENS = (
    "authorization", "password", "passwd", "secret", "private_key", "access_token",
    "refresh_token", "id_token", "client_secret", "api_key", "credential", "cookie",
)


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _labels(item: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = _raw(item)
    value = raw.get("labels") or raw.get("attributes") or raw.get("resource") or {}
    return value if isinstance(value, Mapping) else {}


def _first(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _field(item: Mapping[str, Any], keys: Sequence[str]) -> Any:
    value = _first(item, keys)
    if value not in (None, ""):
        return value
    raw = _raw(item)
    value = _first(raw, keys)
    if value not in (None, ""):
        return value
    return _first(_labels(item), keys)


def _evidence_id(item: Mapping[str, Any], index: int = 0) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _parse_timestamp(value: Any) -> Optional[datetime]:
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


def _numeric(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        candidate = value.strip().lower().replace(",", "")
        multiplier = 1.0
        if candidate.endswith("ms"):
            candidate = candidate[:-2].strip()
        elif candidate.endswith("%"):
            candidate = candidate[:-1].strip()
        elif re.fullmatch(r"[-+]?\d+(?:\.\d+)?[kmgt]", candidate):
            suffix = candidate[-1]
            candidate = candidate[:-1]
            multiplier = {"k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}[suffix]
        try:
            return float(candidate) * multiplier
        except ValueError:
            return None
    return None


def _flatten_text(value: Any, depth: int = 0) -> List[str]:
    if depth >= 4:
        return []
    if isinstance(value, str):
        return [value[:500]]
    if isinstance(value, Mapping):
        parts: List[str] = []
        for key, current in list(value.items())[:50]:
            normalized = str(key).lower().replace("-", "_")
            if any(token in normalized for token in SENSITIVE_TOKENS):
                continue
            parts.extend(_flatten_text(current, depth + 1))
        return parts
    if isinstance(value, (list, tuple)):
        parts: List[str] = []
        for current in list(value)[:16]:
            parts.extend(_flatten_text(current, depth + 1))
        return parts
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    return []


def _text(item: Mapping[str, Any]) -> str:
    return " ".join(_flatten_text(item)).lower()


def _metric_name(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    value = item.get("name") or item.get("metric") or raw.get("name") or raw.get("metric") or raw.get("item_key") or ""
    return str(value).strip().lower()


def _metric_value(item: Mapping[str, Any]) -> Optional[float]:
    raw = _raw(item)
    value = item.get("value") if item.get("value") is not None else _first(raw, ("value", "current", "latest"))
    return _numeric(value)


def _baseline(item: Mapping[str, Any]) -> Dict[str, Optional[float]]:
    raw = _raw(item)
    return {
        "baseline": _numeric(_first(raw, ("baseline", "baseline_value", "pre_incident", "pre_incident_value", "historical_normal", "normal_value"))),
        "p50": _numeric(_first(raw, ("p50", "baseline_p50", "historical_p50"))),
        "p90": _numeric(_first(raw, ("p90", "baseline_p90", "historical_p90"))),
        "p95": _numeric(_first(raw, ("p95", "baseline_p95", "historical_p95"))),
        "p99": _numeric(_first(raw, ("p99", "baseline_p99", "historical_p99"))),
        "growth_rate": _numeric(_first(raw, ("growth_rate", "growth_pct", "trend_pct", "slope_pct"))),
        "baseline_days": _numeric(_first(raw, ("baseline_days", "window_days", "lookback_days"))),
    }


def _incident_start(context: Mapping[str, Any]) -> Optional[datetime]:
    for source in (context, context.get("summary") if isinstance(context.get("summary"), Mapping) else {}):
        if not isinstance(source, Mapping):
            continue
        value = _first(source, ("incident_start", "started_at", "start_time", "created_at"))
        parsed = _parse_timestamp(value)
        if parsed:
            return parsed
    return None


def _metric_kind(name: str, text: str) -> Optional[str]:
    value = f"{name} {text}"
    rules: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
        ("cpu_utilization", ("cpu_util", "cpu_usage", "cpu.percent", "cpu busy", "cpu utilization")),
        ("cpu_cores", ("cpu_cores", "core_count", "logical_cpu", "vcpu_count", "cpu count")),
        ("load", ("load1", "load5", "load15", "load_average", "load average")),
        ("run_queue", ("run_queue", "runqueue", "runnable", "procs_running", "cpu queue")),
        ("iowait", ("iowait", "io_wait", "cpu wait")),
        ("steal", ("steal_time", "cpu_steal", "steal time")),
        ("throttling", ("throttled", "throttling", "cpu cfs")),
        ("softirq", ("softirq", "interrupt pressure", "irq pressure", "interrupt_rate", "interrupts_per")),
        ("memory_available", ("mem_available", "memory_available", "available memory", "available_bytes")),
        ("memory_total", ("mem_total", "memory_total", "total memory", "total_bytes")),
        ("memory_working_set", ("working_set", "memory_usage", "memory_used", "rss", "resident memory")),
        ("memory_cache", ("cached", "page_cache", "memory_cache", "cache_bytes")),
        ("swap_in", ("swapin", "swap_in", "pswpin", "swap in")),
        ("swap_out", ("swapout", "swap_out", "pswpout", "swap out")),
        ("swap_used", ("swap_used", "swap_usage", "swap percent")),
        ("major_faults", ("major_fault", "pgmajfault", "major page fault")),
        ("reclaim", ("reclaim", "kswapd", "direct reclaim", "pgscan", "pgsteal")),
        ("oom", ("oom_kill", "oomkill", "out of memory", "oom event")),
        ("psi_memory", ("psi_memory", "memory psi", "memory_pressure")),
        ("psi_cpu", ("psi_cpu", "cpu psi", "cpu_pressure")),
        ("psi_io", ("psi_io", "io psi", "io_pressure")),
        ("disk_utilization", ("disk_util", "device_util", "io_util", "disk busy", "disk utilization")),
        ("disk_await", ("await", "disk_latency", "io_latency", "device latency")),
        ("disk_queue", ("avgqu", "queue_depth", "disk_queue", "io queue")),
        ("disk_throughput", ("read_bytes", "write_bytes", "throughput", "disk bandwidth")),
        ("disk_iops", ("iops", "read_ops", "write_ops", "disk operations")),
        ("disk_errors", ("disk_error", "device_error", "io_error", "medium error", "device errors")),
        ("filesystem_capacity", ("filesystem_usage", "fs_usage", "disk_space", "filesystem capacity", "filesystem_percent")),
        ("inode_usage", ("inode_usage", "inode_percent", "inodes used", "inode pressure")),
        ("fd_usage", ("file_descriptor", "open_fds", "fd_usage", "file handles")),
        ("process_count", ("process_count", "processes", "proc_count", "tasks")),
        ("conntrack", ("conntrack", "nf_conntrack", "connection tracking")),
        ("entropy", ("entropy", "entropy_avail")),
        ("hardware", ("temperature", "thermal", "sensor", "ecc", "hardware error", "machine check")),
    )
    for kind, tokens in rules:
        if any(token in value for token in tokens):
            return kind
    return None


def _observation(item: Mapping[str, Any], index: int, incident_start: Optional[datetime]) -> Optional[Dict[str, Any]]:
    name = _metric_name(item)
    text = _text(item)
    kind = _metric_kind(name, text)
    value = _metric_value(item)
    if kind is None:
        return None
    stamp = _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at") or _raw(item).get("timestamp"))
    baseline = _baseline(item)
    delta = None
    if value is not None and baseline["baseline"] is not None:
        base = float(baseline["baseline"])
        delta = None if base == 0 else round((value - base) / abs(base), 4)
    return {
        "kind": kind,
        "metric": name or kind,
        "value": value,
        "unit": _field(item, ("unit", "units")),
        "baseline": baseline,
        "relative_delta": delta,
        "evidence_id": _evidence_id(item, index),
        "timestamp": stamp.isoformat() if stamp else None,
        "incident_offset_seconds": round((stamp - incident_start).total_seconds(), 3) if stamp and incident_start else None,
        "host": _field(item, ("host", "hostname", "instance", "node")),
        "device": _field(item, ("device", "disk", "mountpoint", "filesystem")),
        "source": item.get("source"),
    }


def _rows_by_kind(evidence: List[Mapping[str, Any]], incident_start: Optional[datetime]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for index, item in enumerate(evidence):
        if str(item.get("type") or "").lower() not in {"metric", "telemetry", "alert", "event", "log"}:
            continue
        row = _observation(item, index, incident_start)
        if row:
            result[row["kind"]].append(row)
    for rows in result.values():
        rows.sort(key=lambda row: row.get("timestamp") or "")
    return dict(result)


def _max_value(rows: Sequence[Mapping[str, Any]]) -> Optional[float]:
    values = [float(row["value"]) for row in rows if row.get("value") is not None]
    return max(values) if values else None


def _latest_value(rows: Sequence[Mapping[str, Any]]) -> Optional[float]:
    for row in reversed(rows):
        if row.get("value") is not None:
            return float(row["value"])
    return None


def _first_timestamp(rows: Iterable[Mapping[str, Any]]) -> Optional[str]:
    values = [str(row["timestamp"]) for row in rows if row.get("timestamp")]
    return min(values) if values else None


def _ids(rows: Iterable[Mapping[str, Any]], limit: int = 12) -> List[str]:
    result: List[str] = []
    for row in rows:
        value = str(row.get("evidence_id") or "")
        if value and value not in result:
            result.append(value)
        if len(result) >= limit:
            break
    return result


def _event_signals(evidence: List[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups = {
        "oom": ("oom killed", "oom-kill", "out of memory", "oomkiller", "oom event"),
        "kernel_error": ("kernel error", "kernel panic", "machine check", "mce", "general protection fault"),
        "hung_task": ("hung task", "blocked for more than", "soft lockup", "hard lockup"),
        "hardware": ("ecc error", "thermal", "overheat", "sensor fault", "smart failure", "hardware error"),
        "device_error": ("i/o error", "io error", "medium error", "device error", "blk_update_request"),
        "conntrack": ("conntrack table full", "nf_conntrack: table full"),
        "noisy_neighbor": ("noisy neighbor", "noisy-neighbor", "shared host contention"),
    }
    result: Dict[str, List[Dict[str, Any]]] = {key: [] for key in groups}
    for index, item in enumerate(evidence):
        text = _text(item)
        stamp = _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at"))
        row = {"evidence_id": _evidence_id(item, index), "timestamp": stamp.isoformat() if stamp else None}
        for name, tokens in groups.items():
            if any(token in text for token in tokens):
                result[name].append(row)
    return result


def _status_row(
    status: str,
    reason: str,
    rows: Iterable[Mapping[str, Any]],
    incident_start: Optional[datetime],
) -> Dict[str, Any]:
    rows_list = list(rows)
    anomaly_start = _first_timestamp(rows_list)
    anomaly_dt = _parse_timestamp(anomaly_start)
    return {
        "status": status,
        "reason": reason,
        "anomaly_start": anomaly_start,
        "incident_correlation_seconds": round((anomaly_dt - incident_start).total_seconds(), 3) if anomaly_dt and incident_start else None,
        "evidence_ids": _ids(rows_list),
    }


def _cpu_health(rows: Mapping[str, List[Dict[str, Any]]], incident_start: Optional[datetime]) -> Dict[str, Any]:
    util = _max_value(rows.get("cpu_utilization", []))
    cores = _latest_value(rows.get("cpu_cores", []))
    load = _max_value(rows.get("load", []))
    runq = _max_value(rows.get("run_queue", []))
    iowait = _max_value(rows.get("iowait", []))
    steal = _max_value(rows.get("steal", []))
    throttle = _max_value(rows.get("throttling", []))
    psi = _max_value(rows.get("psi_cpu", []))
    softirq = _max_value(rows.get("softirq", []))
    load_ratio = (load / cores) if load is not None and cores not in (None, 0) else None

    saturation = any((
        load_ratio is not None and load_ratio >= 1.0,
        runq is not None and runq >= max(2.0, (cores or 1.0) * 0.5),
        psi is not None and psi >= 10.0,
        throttle is not None and throttle >= 5.0,
    ))
    if util is not None and util >= 80 and not saturation and (iowait is None or iowait < 10) and (steal is None or steal < 5):
        status = "high_utilization_healthy"
        reason = "CPU utilization is high but queue/PSI/throttling evidence does not establish saturation"
    elif saturation:
        status = "saturated"
        reason = "CPU demand exceeds available scheduling capacity or PSI/throttling shows contention"
    elif steal is not None and steal >= 10:
        status = "virtualization_contention"
        reason = "steal time is elevated and points to hypervisor/shared-host contention"
    elif iowait is not None and iowait >= 10:
        status = "waiting_on_io"
        reason = "CPU wait is elevated; storage evidence is required before attributing this to CPU capacity"
    elif softirq is not None and softirq >= 15:
        status = "interrupt_pressure"
        reason = "softirq/interrupt pressure is elevated"
    elif any(value is not None for value in (util, load, runq, iowait, steal, throttle, psi, softirq)):
        status = "healthy_or_not_saturated"
        reason = "available CPU evidence does not establish saturation"
    else:
        status = "unknown"
        reason = "CPU scheduling evidence is insufficient"
    related = sum((rows.get(key, []) for key in ("cpu_utilization", "cpu_cores", "load", "run_queue", "iowait", "steal", "throttling", "psi_cpu", "softirq")), [])
    result = _status_row(status, reason, related, incident_start)
    result["observations"] = {"utilization": util, "cores": cores, "load": load, "load_per_core": round(load_ratio, 3) if load_ratio is not None else None, "run_queue": runq, "iowait": iowait, "steal": steal, "throttling": throttle, "psi_cpu": psi, "softirq": softirq}
    return result


def _memory_health(rows: Mapping[str, List[Dict[str, Any]]], events: Mapping[str, List[Dict[str, Any]]], incident_start: Optional[datetime]) -> Dict[str, Any]:
    available = _latest_value(rows.get("memory_available", []))
    total = _latest_value(rows.get("memory_total", []))
    available_pct = (available / total * 100.0) if available is not None and total not in (None, 0) else None
    swap_in = _max_value(rows.get("swap_in", []))
    swap_out = _max_value(rows.get("swap_out", []))
    major = _max_value(rows.get("major_faults", []))
    reclaim = _max_value(rows.get("reclaim", []))
    psi = _max_value(rows.get("psi_memory", []))
    oom_metric = _max_value(rows.get("oom", []))
    oom = bool(events.get("oom")) or (oom_metric is not None and oom_metric > 0)
    swap_storm = (swap_in is not None and swap_in > 0) and (swap_out is not None and swap_out > 0) and (psi is not None and psi >= 5 or major is not None and major > 0 or available_pct is not None and available_pct < 15)

    if oom:
        status = "oom_pressure"
        reason = "OOM evidence establishes memory exhaustion at least once in the incident window"
    elif swap_storm:
        status = "swap_storm"
        reason = "bidirectional swap activity with memory pressure/page-fault evidence indicates thrashing"
    elif (available_pct is not None and available_pct < 10) or (psi is not None and psi >= 10) or (reclaim is not None and reclaim > 0 and major is not None and major > 0):
        status = "pressured"
        reason = "available memory/PSI/reclaim/page-fault evidence establishes memory pressure"
    elif any(rows.get(key) for key in ("memory_available", "memory_working_set", "memory_cache", "swap_in", "swap_out", "major_faults", "reclaim", "psi_memory")):
        status = "healthy_or_not_pressured"
        reason = "available memory evidence does not establish reclaim/swap/PSI pressure"
    else:
        status = "unknown"
        reason = "memory pressure evidence is insufficient"
    related = sum((rows.get(key, []) for key in ("memory_available", "memory_total", "memory_working_set", "memory_cache", "swap_in", "swap_out", "swap_used", "major_faults", "reclaim", "oom", "psi_memory")), []) + list(events.get("oom", []))
    result = _status_row(status, reason, related, incident_start)
    result["observations"] = {"available": available, "total": total, "available_percent": round(available_pct, 2) if available_pct is not None else None, "swap_in": swap_in, "swap_out": swap_out, "major_page_faults": major, "reclaim": reclaim, "psi_memory": psi, "oom_observed": oom}
    return result


def _disk_health(rows: Mapping[str, List[Dict[str, Any]]], events: Mapping[str, List[Dict[str, Any]]], incident_start: Optional[datetime]) -> Dict[str, Any]:
    util = _max_value(rows.get("disk_utilization", []))
    await_ms = _max_value(rows.get("disk_await", []))
    queue = _max_value(rows.get("disk_queue", []))
    errors = _max_value(rows.get("disk_errors", []))
    fs = _max_value(rows.get("filesystem_capacity", []))
    inode = _max_value(rows.get("inode_usage", []))
    psi = _max_value(rows.get("psi_io", []))
    event_error = bool(events.get("device_error"))
    saturated = any((await_ms is not None and await_ms >= 20, queue is not None and queue >= 2, psi is not None and psi >= 10)) and (util is None or util >= 70)

    if event_error or (errors is not None and errors > 0):
        status = "device_error"
        reason = "device/filesystem I/O errors are present"
    elif inode is not None and inode >= 90:
        status = "inode_pressure"
        reason = "inode consumption is near exhaustion even if byte capacity remains available"
    elif fs is not None and fs >= 90:
        status = "capacity_pressure"
        reason = "filesystem byte capacity is near exhaustion"
    elif saturated:
        status = "io_bottleneck"
        reason = "disk latency/queue/PSI evidence establishes I/O saturation"
    elif util is not None and util >= 80:
        status = "high_utilization_not_yet_saturated"
        reason = "device utilization is high without sufficient latency/queue/PSI evidence of saturation"
    elif any(rows.get(key) for key in ("disk_utilization", "disk_await", "disk_queue", "disk_throughput", "disk_iops", "filesystem_capacity", "inode_usage")):
        status = "healthy_or_not_saturated"
        reason = "available disk evidence does not establish saturation or capacity pressure"
    else:
        status = "unknown"
        reason = "disk evidence is insufficient"
    related = sum((rows.get(key, []) for key in ("disk_utilization", "disk_await", "disk_queue", "disk_throughput", "disk_iops", "disk_errors", "filesystem_capacity", "inode_usage", "psi_io")), []) + list(events.get("device_error", []))
    result = _status_row(status, reason, related, incident_start)
    result["observations"] = {"utilization": util, "await_ms": await_ms, "queue_depth": queue, "device_errors": errors, "filesystem_usage": fs, "inode_usage": inode, "psi_io": psi}
    return result


def _kernel_health(rows: Mapping[str, List[Dict[str, Any]]], events: Mapping[str, List[Dict[str, Any]]], incident_start: Optional[datetime]) -> Dict[str, Any]:
    fd = _max_value(rows.get("fd_usage", []))
    processes = _max_value(rows.get("process_count", []))
    conntrack = _max_value(rows.get("conntrack", []))
    entropy = _latest_value(rows.get("entropy", []))
    hardware = _max_value(rows.get("hardware", []))
    kernel_events = list(events.get("kernel_error", [])) + list(events.get("hung_task", [])) + list(events.get("hardware", [])) + list(events.get("conntrack", []))
    if events.get("kernel_error") or events.get("hung_task") or events.get("hardware"):
        status = "system_fault"
        reason = "kernel/hung-task/hardware event evidence is present"
    elif events.get("conntrack") or (conntrack is not None and conntrack >= 90):
        status = "conntrack_pressure"
        reason = "connection tracking capacity is exhausted or near exhaustion"
    elif fd is not None and fd >= 90:
        status = "fd_pressure"
        reason = "file descriptor utilization is near exhaustion"
    elif entropy is not None and entropy < 128:
        status = "low_entropy_observed"
        reason = "low entropy is observed; causal relevance must be established before escalation"
    elif any(rows.get(key) for key in ("fd_usage", "process_count", "conntrack", "entropy", "hardware", "psi_cpu", "psi_io", "psi_memory")):
        status = "healthy_or_no_system_fault"
        reason = "available system evidence does not establish a kernel/system capacity fault"
    else:
        status = "unknown"
        reason = "kernel/system evidence is insufficient"
    related = sum((rows.get(key, []) for key in ("fd_usage", "process_count", "conntrack", "entropy", "hardware", "psi_cpu", "psi_io", "psi_memory")), []) + kernel_events
    result = _status_row(status, reason, related, incident_start)
    result["observations"] = {"fd_usage": fd, "process_count": processes, "conntrack": conntrack, "entropy": entropy, "hardware_signal": hardware, "kernel_event_count": len(kernel_events)}
    return result


def _capacity(rows: Mapping[str, List[Dict[str, Any]]], incident_start: Optional[datetime]) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    for kind, kind_rows in rows.items():
        for row in kind_rows:
            baseline = row.get("baseline") if isinstance(row.get("baseline"), Mapping) else {}
            if not baseline:
                continue
            candidates.append({
                "kind": kind,
                "metric": row.get("metric"),
                "current": row.get("value"),
                "baseline": baseline.get("baseline"),
                "historical_p95": baseline.get("p95"),
                "historical_p99": baseline.get("p99"),
                "growth_rate": baseline.get("growth_rate"),
                "baseline_days": baseline.get("baseline_days"),
                "relative_delta": row.get("relative_delta"),
                "timestamp": row.get("timestamp"),
                "evidence_id": row.get("evidence_id"),
            })
    sudden = [row for row in candidates if row.get("relative_delta") is not None and abs(float(row["relative_delta"])) >= 0.5]
    growth = [row for row in candidates if row.get("growth_rate") is not None and abs(float(row["growth_rate"])) >= 10]
    percentile = [row for row in candidates if row.get("current") is not None and row.get("historical_p99") is not None and float(row["current"]) > float(row["historical_p99"])]
    baseline_days = [float(row["baseline_days"]) for row in candidates if row.get("baseline_days") is not None]
    return {
        "baseline_available": bool(candidates),
        "multi_day_baseline_available": any(days >= 2 for days in baseline_days),
        "observations": candidates[:24],
        "sudden_saturation_candidates": sudden[:12],
        "growth_trend_candidates": growth[:12],
        "above_historical_p99": percentile[:12],
        "anomaly_start": _first_timestamp(sudden + growth + percentile),
        "policy": "capacity trends and percentiles are supporting observations; they do not replace live saturation/error evidence",
    }


def _causal_patterns(
    rows: Mapping[str, List[Dict[str, Any]]],
    events: Mapping[str, List[Dict[str, Any]]],
    health: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    patterns: List[Dict[str, Any]] = []
    cpu = health.get("cpu", {})
    memory = health.get("memory", {})
    disk = health.get("disk", {})
    if cpu.get("status") == "high_utilization_healthy":
        patterns.append({"pattern": "high_utilization_but_healthy", "confidence": "observed", "evidence_ids": cpu.get("evidence_ids", []), "handoff": None})
    if cpu.get("status") == "saturated":
        patterns.append({"pattern": "cpu_saturation", "confidence": "observed", "evidence_ids": cpu.get("evidence_ids", []), "handoff": None})
    if cpu.get("status") == "waiting_on_io" and disk.get("status") in {"io_bottleneck", "device_error"}:
        patterns.append({"pattern": "storage_bottleneck_expressed_as_cpu_iowait", "confidence": "strong", "evidence_ids": list(dict.fromkeys(cpu.get("evidence_ids", []) + disk.get("evidence_ids", [])))[:16], "handoff": "storage"})
    softirq = _max_value(rows.get("softirq", []))
    if softirq is not None and softirq >= 15:
        patterns.append({"pattern": "network_interrupt_pressure_candidate", "confidence": "candidate", "evidence_ids": _ids(rows.get("softirq", [])), "handoff": "network"})
    steal = _max_value(rows.get("steal", []))
    if steal is not None and steal >= 10:
        patterns.append({"pattern": "vm_steal_or_noisy_neighbor_candidate", "confidence": "strong" if events.get("noisy_neighbor") else "candidate", "evidence_ids": _ids(rows.get("steal", [])) + _ids(events.get("noisy_neighbor", [])), "handoff": "vm"})
    growth_rows = []
    for key in ("memory_working_set", "fd_usage", "process_count", "inode_usage"):
        growth_rows.extend([row for row in rows.get(key, []) if isinstance(row.get("baseline"), Mapping) and row["baseline"].get("growth_rate") is not None and float(row["baseline"]["growth_rate"]) >= 10])
    if growth_rows:
        patterns.append({"pattern": "resource_leak_candidate", "confidence": "candidate", "evidence_ids": _ids(growth_rows), "handoff": "application"})
    app_pressure_ids: List[str] = []
    for key in ("cpu_utilization", "memory_working_set"):
        for row in rows.get(key, []):
            metric = str(row.get("metric") or "")
            if any(token in metric for token in ("process_", "app_", "container_", "service_")):
                app_pressure_ids.extend(_ids([row]))
    if app_pressure_ids and (cpu.get("status") == "saturated" or memory.get("status") in {"pressured", "swap_storm", "oom_pressure"}):
        patterns.append({"pattern": "host_pressure_with_application_resource_contribution", "confidence": "candidate", "evidence_ids": list(dict.fromkeys(app_pressure_ids + cpu.get("evidence_ids", []) + memory.get("evidence_ids", [])))[:16], "handoff": "application"})
    return patterns[:12]


def build_infrastructure_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build bounded deterministic USE/saturation evidence before LLM synthesis."""
    items = [item for item in evidence if isinstance(item, Mapping)]
    ctx = context or {}
    start = _incident_start(ctx)
    rows = _rows_by_kind(items, start)
    events = _event_signals(items)
    health = {
        "cpu": _cpu_health(rows, start),
        "memory": _memory_health(rows, events, start),
        "disk": _disk_health(rows, events, start),
        "kernel_system": _kernel_health(rows, events, start),
    }
    capacity = _capacity(rows, start)
    health["capacity"] = {
        "status": "trend_risk" if capacity["sudden_saturation_candidates"] or capacity["growth_trend_candidates"] or capacity["above_historical_p99"] else "baseline_available" if capacity["baseline_available"] else "unknown",
        "reason": "capacity baseline contains sudden/growth/percentile anomalies" if capacity["sudden_saturation_candidates"] or capacity["growth_trend_candidates"] or capacity["above_historical_p99"] else "capacity baseline is available without a deterministic trend anomaly" if capacity["baseline_available"] else "multi-day baseline/percentile/growth evidence is missing",
        "anomaly_start": capacity.get("anomaly_start"),
        "incident_correlation_seconds": None,
        "evidence_ids": _ids(capacity["sudden_saturation_candidates"] + capacity["growth_trend_candidates"] + capacity["above_historical_p99"]),
        "observations": {"multi_day_baseline_available": capacity["multi_day_baseline_available"], "growth_candidates": len(capacity["growth_trend_candidates"]), "above_historical_p99": len(capacity["above_historical_p99"])},
    }
    if health["capacity"].get("anomaly_start") and start:
        anomaly = _parse_timestamp(health["capacity"]["anomaly_start"])
        if anomaly:
            health["capacity"]["incident_correlation_seconds"] = round((anomaly - start).total_seconds(), 3)

    causal_patterns = _causal_patterns(rows, events, health)
    handoffs = []
    for pattern in causal_patterns:
        target = pattern.get("handoff")
        if target and target not in handoffs:
            handoffs.append(target)

    present_kinds = set(rows)
    gaps: List[Dict[str, Any]] = []
    gap_rules = [
        ("cpu_scheduling", {"cpu_utilization", "load", "run_queue", "psi_cpu"}, 0.95, "utilization alone cannot establish CPU saturation"),
        ("memory_pressure", {"memory_available", "swap_in", "swap_out", "major_faults", "psi_memory"}, 0.95, "memory usage percentage alone cannot distinguish cache from pressure/thrashing"),
        ("disk_latency_queue", {"disk_await", "disk_queue", "psi_io"}, 0.92, "disk utilization alone cannot establish an I/O bottleneck"),
        ("capacity_baseline", set(), 0.80, "multi-day baseline, percentile and growth trend improve capacity diagnosis"),
        ("kernel_system", {"fd_usage", "conntrack"}, 0.70, "kernel/system capacity evidence is incomplete"),
    ]
    for name, expected, gain, reason in gap_rules:
        if name == "capacity_baseline":
            missing = not capacity["multi_day_baseline_available"]
        else:
            missing = not expected.intersection(present_kinds)
        if missing:
            gaps.append({"evidence": name, "information_gain": gain, "reason": reason})
    gaps.sort(key=lambda row: float(row["information_gain"]), reverse=True)

    type_counts = Counter(str(item.get("type") or "unknown").lower() for item in items)
    return {
        "policy": "USE observations before thresholds; utilization_is_not_saturation; causal attribution requires corroborating live evidence",
        "service": service_name,
        "incident_start": start.isoformat() if start else None,
        "evidence_count": len(items),
        "evidence_type_counts": dict(type_counts),
        "metric_kinds": {kind: values[:16] for kind, values in rows.items()},
        "event_signals": events,
        "health_matrix": health,
        "capacity_analysis": capacity,
        "causal_patterns": causal_patterns,
        "handoff_candidates": handoffs,
        "evidence_gaps": gaps[:10],
        "next_best_evidence": gaps[:6],
    }
