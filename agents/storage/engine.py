from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _labels(item: Mapping[str, Any]) -> Mapping[str, Any]:
    for value in (_raw(item).get("labels"), item.get("labels")):
        if isinstance(value, Mapping):
            return value
    return {}


def _eid(item: Mapping[str, Any], index: int) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _lookup(item: Mapping[str, Any], *keys: str) -> Any:
    raw = _raw(item)
    labels = _labels(item)
    for source in (raw, labels, item):
        for key in keys:
            value = source.get(key)
            if value not in (None, ""):
                return value
    return None


def _text(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    values = [
        item.get("name"), item.get("message"), item.get("value"),
        raw.get("diagnostic"), raw.get("event"), raw.get("reason"), raw.get("error"),
        raw.get("status"), raw.get("state"), raw.get("health"), raw.get("detail"),
    ]
    return " ".join(str(value) for value in values if value not in (None, "")).lower()


def _number(value: Any) -> Optional[float]:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            value = value.strip().rstrip("%").replace(",", "")
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "ok", "healthy", "up", "mounted", "active", "ready", "success"}:
        return True
    if normalized in {"0", "false", "no", "failed", "down", "unmounted", "inactive", "notready", "error"}:
        return False
    return None


def _ratio(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    return value / 100.0 if value > 1.5 else value


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
    for value in (
        item.get("observed_at"), item.get("timestamp"), item.get("created_at"),
        _lookup(item, "@timestamp", "timestamp", "time"),
    ):
        parsed = _parse_time(value)
        if parsed:
            return parsed
    return None


def _metric(item: Mapping[str, Any]) -> Tuple[str, Optional[float]]:
    name = str(item.get("name") or item.get("metric") or _lookup(item, "metric", "item_key") or "").lower()
    value = item.get("value") if item.get("value") is not None else _lookup(item, "value", "current", "current_value")
    return name, _number(value)


def _resource(item: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "host": str(_lookup(item, "host", "hostname", "node", "instance") or "unknown")[:180],
        "device": str(_lookup(item, "device", "disk", "block_device", "dev") or "unknown")[:180],
        "filesystem": str(_lookup(item, "filesystem", "fs", "fstype") or "unknown")[:120],
        "mount": str(_lookup(item, "mount", "mountpoint", "mount_point", "path") or "unknown")[:240],
        "volume": str(_lookup(item, "volume", "pvc", "pv", "persistent_volume", "claim") or "unknown")[:180],
    }


def _window(items: Sequence[Mapping[str, Any]], context: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    supplied = context.get("time_range")
    if isinstance(supplied, Mapping):
        start = supplied.get("start") or supplied.get("from")
        end = supplied.get("end") or supplied.get("to")
        if start or end:
            return {"start": str(start) if start else None, "end": str(end) if end else None}
    start = context.get("incident_start") or context.get("started_at")
    end = context.get("incident_end") or context.get("ended_at")
    if start or end:
        return {"start": str(start) if start else None, "end": str(end) if end else None}
    stamps = sorted(stamp for stamp in (_timestamp(item) for item in items) if stamp)
    return {"start": stamps[0].isoformat() if stamps else None, "end": stamps[-1].isoformat() if stamps else None}


METRIC_ALIASES: Dict[str, Tuple[str, ...]] = {
    "capacity_utilization": ("filesystem_usage", "disk_usage", "capacity_utilization", "storage_used_percent", "filesystem_used_percent"),
    "capacity_free": ("filesystem_free_percent", "disk_free_percent", "capacity_free_percent"),
    "growth_rate": ("storage_growth_rate", "disk_growth_rate", "capacity_growth_rate", "growth_percent_per_day"),
    "inode_utilization": ("inode_utilization", "inode_usage", "inodes_used_percent", "filesystem_inode_usage"),
    "inode_free": ("files_free", "inodes_free", "inode_free"),
    "iops": ("iops", "disk_ops", "io_operations", "reads_per_second", "writes_per_second"),
    "throughput": ("throughput", "bytes_per_second", "disk_read_bytes", "disk_write_bytes", "io_bytes"),
    "latency": ("await", "disk_latency", "io_latency", "read_latency", "write_latency", "storage_latency"),
    "queue_depth": ("queue_depth", "avgqu", "disk_queue", "io_queue"),
    "utilization": ("disk_utilization", "device_utilization", "io_utilization", "busy_percent"),
    "device_errors": ("device_errors", "disk_errors", "io_errors", "media_errors", "nvme_media_errors"),
    "storage_throttling": ("storage_throttling", "io_throttling", "throttled_io", "disk_throttle"),
    "ceph_slow_ops": ("ceph_slow_ops", "slow_ops"),
    "ceph_degraded": ("ceph_degraded_objects", "degraded_objects", "ceph_degraded_ratio"),
    "ceph_recovery": ("ceph_recovery", "ceph_backfill", "recovery_bytes", "backfill_bytes"),
    "application_write_rate": ("application_write", "app_write", "write_requests", "write_rate"),
    "database_write_rate": ("database_write", "db_write", "wal_bytes", "checkpoint_write", "database_iops"),
}


def _metric_rows(items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    rows = {key: [] for key in METRIC_ALIASES}
    for index, item in enumerate(items):
        name, value = _metric(item)
        if not name:
            continue
        for feature, aliases in METRIC_ALIASES.items():
            if not any(alias in name for alias in aliases):
                continue
            rows[feature].append({
                "evidence_id": _eid(item, index),
                "metric": name,
                "value": value,
                **_resource(item),
                "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
            })
    return rows


def _last(rows: Mapping[str, List[Dict[str, Any]]], feature: str) -> Optional[float]:
    values = rows.get(feature) or []
    return _number(values[-1].get("value")) if values else None


def _explicit_state(items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {
        "filesystem": [], "mount": [], "device_health": [], "smart": [], "multipath": [],
        "persistent_volume": [], "ceph": [], "events": [],
    }
    for index, item in enumerate(items):
        raw = _raw(item)
        text = _text(item)
        common = {
            "evidence_id": _eid(item, index),
            **_resource(item),
            "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
        }
        diagnostic = str(raw.get("diagnostic") or _lookup(item, "diagnostic", "kind", "subtype") or "").lower()

        readonly = _bool(_lookup(item, "read_only", "readonly", "filesystem_read_only"))
        fs_error = _lookup(item, "filesystem_error", "fs_error")
        if readonly is True or fs_error not in (None, "") or any(token in text for token in ("read-only file system", "filesystem error", "ext4-fs error", "xfs error", "corruption")):
            result["filesystem"].append({
                **common,
                "read_only": True if readonly is True or "read-only file system" in text else readonly,
                "error": str(fs_error or text)[:320],
                "corruption_symptom": any(token in text for token in ("corrupt", "ext4-fs error", "xfs error", "metadata error")),
            })

        mounted = _bool(_lookup(item, "mounted", "mount_state", "is_mounted"))
        if mounted is not None or diagnostic in {"mount", "filesystem_mount"} or any(token in text for token in ("mount failed", "not mounted", "unmounted")):
            if "mount failed" in text or "not mounted" in text or "unmounted" in text:
                mounted = False
            result["mount"].append({**common, "mounted": mounted, "reason": str(_lookup(item, "reason", "mount_error") or text)[:300]})

        protocol = str(_lookup(item, "device_protocol", "protocol", "transport") or "").lower()
        health = str(_lookup(item, "device_health", "health_status", "nvme_health", "scsi_health", "sata_health") or "").lower()
        critical_warning = _number(_lookup(item, "critical_warning", "nvme_critical_warning"))
        if protocol in {"nvme", "sata", "scsi"} or health or critical_warning is not None or diagnostic in {"device_health", "nvme_health", "scsi_health", "sata_health"}:
            result["device_health"].append({
                **common, "protocol": protocol or "unknown", "health": health or "unknown",
                "critical_warning": critical_warning,
                "media_errors": _number(_lookup(item, "media_errors", "uncorrectable_errors")),
            })

        smart_status = str(_lookup(item, "smart_status", "smart_health", "smart_overall_health") or "").lower()
        pending = _number(_lookup(item, "current_pending_sector", "pending_sectors"))
        reallocated = _number(_lookup(item, "reallocated_sector_count", "reallocated_sectors"))
        uncorrectable = _number(_lookup(item, "offline_uncorrectable", "uncorrectable_sectors"))
        if smart_status or pending is not None or reallocated is not None or uncorrectable is not None or diagnostic == "smart":
            result["smart"].append({
                **common, "status": smart_status or "unknown", "pending_sectors": pending,
                "reallocated_sectors": reallocated, "uncorrectable_sectors": uncorrectable,
                "interpretation_policy": "SMART warning is risk evidence, not proof of imminent physical failure",
            })

        path_state = str(_lookup(item, "path_state", "multipath_state", "path_status") or "").lower()
        active_paths = _number(_lookup(item, "active_paths", "paths_active"))
        failed_paths = _number(_lookup(item, "failed_paths", "paths_failed"))
        if path_state or active_paths is not None or failed_paths is not None or diagnostic in {"multipath", "storage_path"}:
            result["multipath"].append({
                **common, "state": path_state or "unknown", "active_paths": active_paths, "failed_paths": failed_paths,
            })

        pv_state = str(_lookup(item, "pv_state", "pvc_state", "volume_state", "phase") or "").lower()
        attach_error = _lookup(item, "attach_error", "volume_attach_error")
        mount_error = _lookup(item, "mount_error", "volume_mount_error")
        if pv_state or attach_error not in (None, "") or mount_error not in (None, "") or diagnostic in {"pv", "pvc", "persistent_volume", "volume_attach", "volume_mount"}:
            result["persistent_volume"].append({
                **common, "state": pv_state or "unknown", "attach_error": str(attach_error)[:260] if attach_error else None,
                "mount_error": str(mount_error)[:260] if mount_error else None,
            })

        cephish = diagnostic.startswith("ceph") or any(key in raw for key in ("osd_state", "pg_state", "degraded_objects", "slow_ops", "backfill_state", "replica_health"))
        if cephish:
            result["ceph"].append({
                **common,
                "osd_state": str(_lookup(item, "osd_state") or "unknown").lower(),
                "pg_state": str(_lookup(item, "pg_state", "placement_group_state") or "unknown").lower(),
                "degraded": _number(_lookup(item, "degraded_objects", "degraded_ratio")),
                "slow_ops": _number(_lookup(item, "slow_ops")),
                "recovery_backfill": str(_lookup(item, "recovery_state", "backfill_state") or "unknown").lower(),
                "replica_health": str(_lookup(item, "replica_health", "replica_state") or "unknown").lower(),
            })

        if any(token in text for token in ("i/o error", "input/output error", "no space left on device", "read-only file system", "mount failed", "attach failed", "slow ops", "device error")):
            result["events"].append({**common, "message": text[:320]})
    return result


def _capacity_analysis(rows: Mapping[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    used = _ratio(_last(rows, "capacity_utilization"))
    free = _ratio(_last(rows, "capacity_free"))
    if used is None and free is not None:
        used = max(0.0, 1.0 - free)
    inode_used = _ratio(_last(rows, "inode_utilization"))
    inode_free = _last(rows, "inode_free")
    growth = _last(rows, "growth_rate")
    return {
        "capacity_utilization": used,
        "capacity_free": free,
        "growth_rate": growth,
        "inode_utilization": inode_used,
        "inode_free": inode_free,
    }


def _io_analysis(rows: Mapping[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    return {
        "iops": _last(rows, "iops"),
        "throughput": _last(rows, "throughput"),
        "latency_await_ms": _last(rows, "latency"),
        "queue_depth": _last(rows, "queue_depth"),
        "utilization": _ratio(_last(rows, "utilization")),
        "device_errors": _last(rows, "device_errors"),
        "storage_throttling": _last(rows, "storage_throttling"),
    }


def _first_anomaly_time(items: Sequence[Mapping[str, Any]], rows: Mapping[str, List[Dict[str, Any]]], states: Mapping[str, List[Dict[str, Any]]]) -> Optional[datetime]:
    candidate_ids = set()
    for feature, threshold in (("latency", 20.0), ("queue_depth", 2.0), ("device_errors", 0.0), ("storage_throttling", 0.0)):
        for row in rows.get(feature, []):
            value = _number(row.get("value"))
            if value is not None and value > threshold:
                candidate_ids.add(str(row["evidence_id"]))
    for key in ("filesystem", "multipath", "persistent_volume", "ceph"):
        candidate_ids.update(str(row["evidence_id"]) for row in states[key])
    stamps = []
    for index, item in enumerate(items):
        if _eid(item, index) in candidate_ids:
            stamp = _timestamp(item)
            if stamp:
                stamps.append(stamp)
    return min(stamps) if stamps else None


def _domain_incident_times(items: Sequence[Mapping[str, Any]], context: Mapping[str, Any]) -> Dict[str, List[datetime]]:
    result: Dict[str, List[datetime]] = {"application": [], "database": []}
    for item in items:
        text = _text(item)
        domain = str(_lookup(item, "domain", "agent", "component_type", "signal_domain") or "").lower()
        stamp = _timestamp(item)
        if not stamp:
            continue
        if domain in {"application", "app"} or any(token in text for token in ("application latency", "http error", "request latency", "app incident")):
            result["application"].append(stamp)
        if domain in {"database", "db"} or any(token in text for token in ("database latency", "checkpoint", "wal pressure", "db incident", "database write")):
            result["database"].append(stamp)
    for domain in ("application", "database"):
        raw = context.get(f"{domain}_incident_start")
        parsed = _parse_time(raw)
        if parsed:
            result[domain].append(parsed)
    return result


def _temporal_correlation(items: Sequence[Mapping[str, Any]], rows: Mapping[str, List[Dict[str, Any]]], states: Mapping[str, List[Dict[str, Any]]], context: Mapping[str, Any]) -> Dict[str, Any]:
    storage_start = _first_anomaly_time(items, rows, states)
    domain_times = _domain_incident_times(items, context)
    correlations = []
    for domain, values in domain_times.items():
        if not storage_start or not values:
            continue
        incident_start = min(values)
        delta = (storage_start - incident_start).total_seconds()
        correlations.append({
            "domain": domain,
            "storage_anomaly_start": storage_start.isoformat(),
            "domain_incident_start": incident_start.isoformat(),
            "delta_seconds_storage_minus_domain": delta,
            "ordering": "storage_precedes" if delta < -5 else "domain_precedes" if delta > 5 else "near_simultaneous",
            "causal_policy": "temporal ordering is evidence for falsification, not causal proof",
        })
    return {
        "storage_anomaly_start": storage_start.isoformat() if storage_start else None,
        "correlations": correlations,
    }


_FALSIFICATION = {
    "disk_full": "Capacity falls below the exhaustion threshold while write failures persist on the same filesystem.",
    "inode_full": "Inodes are demonstrably available while ENOSPC/inode-related write failures persist.",
    "io_saturation": "Latency/queue remain elevated while device utilization, throttling and workload I/O are below saturation.",
    "failing_physical_device": "Independent device telemetry is healthy and media/I/O errors do not recur under equivalent load.",
    "networked_storage_latency": "Storage paths/replicas are healthy and latency persists without multipath, attach, Ceph or remote-storage degradation.",
    "filesystem_corruption_symptom": "Filesystem integrity checks/logs show no filesystem errors while the read-only/corruption symptom reproduces.",
    "application_write_burst": "Application write rate returns to baseline while storage pressure remains unchanged.",
    "database_driven_storage_pressure": "Database write/WAL/checkpoint pressure returns to baseline while the same storage latency/queue pressure persists.",
    "distributed_storage_degraded": "OSD/PG/replica health is normal with no slow ops or recovery/backfill pressure while storage symptoms persist.",
    "persistent_volume_path_issue": "PV/PVC is bound/attached/mounted and all paths are healthy while the workload still observes the storage failure.",
    "healthy_busy_storage": "The device remains high-throughput/high-utilization but latency, queue, errors and throttling stay healthy while the incident persists elsewhere.",
}


def _cause_candidates(
    rows: Mapping[str, List[Dict[str, Any]]],
    states: Mapping[str, List[Dict[str, Any]]],
    capacity: Mapping[str, Any],
    io: Mapping[str, Any],
    temporal: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    def add(code: str, evidence_ids: Iterable[Any], basis: str, confidence: float, handoff: Optional[str] = None, role: str = "storage_origin_candidate") -> None:
        ids = list(dict.fromkeys(str(value) for value in evidence_ids if value not in (None, "")))[:20]
        candidates.append({
            "code": code,
            "evidence_ids": ids,
            "basis": basis,
            "confidence": max(0.0, min(1.0, confidence)),
            "handoff": handoff,
            "causal_role": role,
            "root_cause_status": "candidate_requires_falsification",
            "expected_falsification_result": _FALSIFICATION[code],
        })

    capacity_ids = [row["evidence_id"] for key in ("capacity_utilization", "capacity_free") for row in rows.get(key, [])]
    inode_ids = [row["evidence_id"] for key in ("inode_utilization", "inode_free") for row in rows.get(key, [])]
    used = capacity.get("capacity_utilization")
    free = capacity.get("capacity_free")
    inode_used = capacity.get("inode_utilization")
    inode_free = capacity.get("inode_free")
    if (used is not None and used >= 0.95) or (free is not None and free <= 0.05):
        add("disk_full", capacity_ids, "filesystem capacity is at or near exhaustion", 0.92, handoff="infrastructure")
    if (inode_used is not None and inode_used >= 0.95) or (inode_free is not None and inode_free <= 0):
        add("inode_full", inode_ids, "inode availability is exhausted or critically low", 0.94, handoff="infrastructure")

    latency = io.get("latency_await_ms")
    queue = io.get("queue_depth")
    utilization = io.get("utilization")
    throttling = io.get("storage_throttling")
    io_ids = [row["evidence_id"] for key in ("latency", "queue_depth", "utilization", "iops", "throughput", "storage_throttling") for row in rows.get(key, [])]
    if ((latency is not None and latency >= 20 and queue is not None and queue >= 2) or
        (utilization is not None and utilization >= 0.9 and latency is not None and latency >= 20) or
        (throttling is not None and throttling > 0 and latency is not None and latency >= 20)):
        add("io_saturation", io_ids, "elevated await/latency is corroborated by queue, utilization or throttling pressure", 0.84, handoff="infrastructure")

    device_ids = [row["evidence_id"] for row in states["device_health"] + states["smart"]]
    device_error_ids = [row["evidence_id"] for row in rows.get("device_errors", [])]
    hard_device_fault = any(
        row.get("health") in {"failed", "critical", "degraded", "unhealthy"}
        or (row.get("critical_warning") or 0) > 0
        or (row.get("media_errors") or 0) > 0
        for row in states["device_health"]
    ) or (io.get("device_errors") is not None and io.get("device_errors") > 0)
    smart_warning = any(
        row.get("status") in {"failed", "failing", "warning", "prefail", "bad"}
        or (row.get("pending_sectors") or 0) > 0
        or (row.get("uncorrectable_sectors") or 0) > 0
        for row in states["smart"]
    )
    if hard_device_fault:
        add("failing_physical_device", device_ids + device_error_ids, "device/media/I/O health evidence indicates a physical-device fault candidate", 0.88, handoff="recovery")
    elif smart_warning:
        add("failing_physical_device", device_ids, "SMART indicators raise device-risk suspicion but do not prove imminent failure", 0.58, handoff="recovery")

    filesystem_bad = [row for row in states["filesystem"] if row.get("read_only") is True or row.get("corruption_symptom")]
    if filesystem_bad:
        add("filesystem_corruption_symptom", [row["evidence_id"] for row in filesystem_bad], "filesystem error/read-only/corruption symptom observed", 0.78, handoff="recovery")

    path_bad = [row for row in states["multipath"] if row.get("state") in {"failed", "degraded", "faulty", "down"} or (row.get("failed_paths") or 0) > 0]
    pv_bad = [row for row in states["persistent_volume"] if row.get("state") in {"pending", "failed", "lost", "detached"} or row.get("attach_error") or row.get("mount_error")]
    if path_bad or pv_bad:
        add("persistent_volume_path_issue", [row["evidence_id"] for row in path_bad + pv_bad], "multipath/PV attach-or-mount evidence shows a storage path problem", 0.83, handoff="kubernetes")

    ceph_bad = [
        row for row in states["ceph"]
        if row.get("osd_state") in {"down", "out", "failed"}
        or any(token in row.get("pg_state", "") for token in ("degraded", "undersized", "inactive", "peering", "stale"))
        or (row.get("degraded") or 0) > 0
        or (row.get("slow_ops") or 0) > 0
        or row.get("replica_health") in {"degraded", "failed", "unhealthy"}
        or row.get("recovery_backfill") in {"active", "recovering", "backfilling", "degraded"}
    ]
    ceph_metric_bad = (_last(rows, "ceph_slow_ops") or 0) > 0 or (_last(rows, "ceph_degraded") or 0) > 0
    if ceph_bad or ceph_metric_bad:
        ids = [row["evidence_id"] for row in ceph_bad] + [row["evidence_id"] for key in ("ceph_slow_ops", "ceph_degraded", "ceph_recovery") for row in rows.get(key, [])]
        add("distributed_storage_degraded", ids, "distributed storage has OSD/PG/slow-op/degraded/recovery pressure", 0.87, handoff="infrastructure")
        if latency is not None and latency >= 20:
            add("networked_storage_latency", ids + [row["evidence_id"] for row in rows.get("latency", [])], "remote/distributed storage degradation coincides with elevated storage latency", 0.82, handoff="network")
    elif path_bad and latency is not None and latency >= 20:
        add("networked_storage_latency", [row["evidence_id"] for row in path_bad] + [row["evidence_id"] for row in rows.get("latency", [])], "path degradation coincides with elevated storage latency", 0.78, handoff="network")

    app_write = _last(rows, "application_write_rate")
    db_write = _last(rows, "database_write_rate")
    pressure_present = any(row["code"] == "io_saturation" for row in candidates) or (latency is not None and latency >= 20)
    if pressure_present and app_write is not None and app_write > 0:
        add("application_write_burst", [row["evidence_id"] for row in rows.get("application_write_rate", [])] + io_ids, "application write activity overlaps storage pressure", 0.68, handoff="application", role="workload_driven_pressure_candidate")
    if pressure_present and db_write is not None and db_write > 0:
        add("database_driven_storage_pressure", [row["evidence_id"] for row in rows.get("database_write_rate", [])] + io_ids, "database write/WAL/checkpoint activity overlaps storage pressure", 0.74, handoff="database", role="workload_driven_pressure_candidate")

    for correlation in temporal.get("correlations", []):
        if correlation.get("domain") == "database" and correlation.get("ordering") == "domain_precedes" and pressure_present and not any(row["code"] == "database_driven_storage_pressure" for row in candidates):
            add("database_driven_storage_pressure", [], "database incident precedes storage anomaly; verify workload-driven I/O before blaming storage", 0.52, handoff="database", role="workload_driven_pressure_candidate")
        if correlation.get("domain") == "application" and correlation.get("ordering") == "domain_precedes" and pressure_present and not any(row["code"] == "application_write_burst" for row in candidates):
            add("application_write_burst", [], "application incident precedes storage anomaly; verify write amplification before blaming storage", 0.5, handoff="application", role="workload_driven_pressure_candidate")

    severe_codes = {"disk_full", "inode_full", "failing_physical_device", "filesystem_corruption_symptom", "networked_storage_latency", "distributed_storage_degraded", "persistent_volume_path_issue"}
    high_busy = utilization is not None and utilization >= 0.75
    low_latency = latency is None or latency < 10
    low_queue = queue is None or queue < 2
    no_errors = (io.get("device_errors") in (None, 0)) and not filesystem_bad and not path_bad and not pv_bad and not ceph_bad
    if high_busy and low_latency and low_queue and no_errors and not any(row["code"] in severe_codes for row in candidates):
        ids = [row["evidence_id"] for key in ("utilization", "iops", "throughput", "latency", "queue_depth") for row in rows.get(key, [])]
        add("healthy_busy_storage", ids, "storage is busy but latency, queue and error signals remain healthy", 0.88, handoff="application", role="storage_not_primary_candidate")

    return candidates[:18]


def build_storage_reliability_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    ctx = context if isinstance(context, Mapping) else {}
    rows = _metric_rows(items)
    states = _explicit_state(items)
    capacity = _capacity_analysis(rows)
    io = _io_analysis(rows)
    temporal = _temporal_correlation(items, rows, states, ctx)
    candidates = _cause_candidates(rows, states, capacity, io, temporal)

    storage_origin = [row for row in candidates if row.get("causal_role") == "storage_origin_candidate"]
    workload_pressure = [row for row in candidates if row.get("causal_role") == "workload_driven_pressure_candidate"]
    healthy_busy = any(row.get("code") == "healthy_busy_storage" for row in candidates)
    if storage_origin:
        attribution = "storage_is_plausible_cause_candidate"
    elif workload_pressure:
        attribution = "storage_appears_pressured_by_workload_candidate"
    elif healthy_busy:
        attribution = "storage_busy_but_not_currently_faulted"
    else:
        attribution = "insufficient_evidence_to_attribute_storage"

    handoffs: List[str] = []
    for row in candidates:
        target = row.get("handoff")
        if target and target != "storage" and target not in handoffs:
            handoffs.append(str(target))

    gaps: List[Dict[str, Any]] = []
    if capacity.get("capacity_utilization") is None and capacity.get("capacity_free") is None:
        gaps.append({"evidence": "filesystem/device capacity utilization and growth rate", "information_gain": 0.96})
    if capacity.get("inode_utilization") is None and capacity.get("inode_free") is None:
        gaps.append({"evidence": "inode utilization/free count", "information_gain": 0.92})
    if io.get("latency_await_ms") is None or io.get("queue_depth") is None or io.get("utilization") is None:
        gaps.append({"evidence": "I/O await/latency, queue depth and device utilization for the incident window", "information_gain": 0.95})
    if not states["device_health"] and not states["smart"]:
        gaps.append({"evidence": "NVMe/SATA/SCSI or SMART device-health telemetry when available", "information_gain": 0.78})
    if not states["mount"] and not states["filesystem"]:
        gaps.append({"evidence": "mount state and filesystem/kernel error evidence", "information_gain": 0.86})
    if not states["multipath"]:
        gaps.append({"evidence": "multipath/remote-storage path state when networked storage is used", "information_gain": 0.73})
    if not states["persistent_volume"]:
        gaps.append({"evidence": "PV/PVC attach and mount state when persistent volumes are involved", "information_gain": 0.72})
    if not temporal.get("storage_anomaly_start"):
        gaps.append({"evidence": "timestamped storage anomaly plus application/database incident start", "information_gain": 0.84})
    gaps.sort(key=lambda row: float(row["information_gain"]), reverse=True)

    return {
        "policy": "storage alerts are symptoms until cross-layer evidence distinguishes storage-originated failure from workload-driven pressure",
        "smart_policy": "SMART warnings are probabilistic risk evidence and never proof that a device is certainly or imminently failing",
        "service": service_name,
        "time_window": _window(items, ctx),
        "capacity_analysis": capacity,
        "io_analysis": io,
        "filesystem_analysis": {"filesystem": states["filesystem"], "mounts": states["mount"]},
        "device_health_analysis": {"device": states["device_health"], "smart": states["smart"]},
        "path_analysis": {"multipath": states["multipath"], "persistent_volumes": states["persistent_volume"]},
        "distributed_storage_analysis": {
            "ceph": states["ceph"],
            "slow_ops": _last(rows, "ceph_slow_ops"),
            "degraded": _last(rows, "ceph_degraded"),
            "recovery_backfill": _last(rows, "ceph_recovery"),
        },
        "event_chronology": sorted(states["events"], key=lambda row: row.get("timestamp") or "")[:40],
        "temporal_correlation": temporal,
        "cause_candidates": candidates,
        "causal_attribution": attribution,
        "storage_origin_candidates": storage_origin,
        "workload_pressure_candidates": workload_pressure,
        "handoff_candidates": handoffs[:8],
        "evidence_gaps": gaps[:8],
        "next_best_evidence": gaps[:6],
        "analysis_stages": [
            "capacity_inode", "io_performance", "filesystem_mount", "device_smart", "multipath_persistent_volume",
            "distributed_storage", "event_chronology", "application_database_temporal_correlation", "causal_attribution",
        ],
    }
