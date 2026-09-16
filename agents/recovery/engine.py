from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _field(item: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for source in (item, _raw(item)):
        for key in keys:
            value = source.get(key)
            if value not in (None, ""):
                return value
    return None


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
    return _parse_time(
        item.get("observed_at")
        or item.get("timestamp")
        or item.get("created_at")
        or _field(item, ("backup_time", "completion_time", "completed_at", "restore_point_time", "snapshot_time"))
    )


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _numeric(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        candidate = value.strip().lower().replace(",", "").rstrip("%")
        try:
            return float(candidate)
        except ValueError:
            return None
    return None


def _bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "success", "succeeded", "healthy", "available", "complete", "completed", "ok"}:
            return True
        if normalized in {"false", "no", "0", "failed", "unhealthy", "unavailable", "broken", "missing"}:
            return False
    return None


def _unique(values: Iterable[Any], limit: int = 24) -> List[str]:
    result: List[str] = []
    for raw in values:
        if raw in (None, ""):
            continue
        value = str(raw).strip()
        if value and value not in result:
            result.append(value)
        if len(result) >= limit:
            break
    return result


def _text(item: Mapping[str, Any]) -> str:
    values: List[str] = []
    for source in (item, _raw(item)):
        for key, value in list(source.items())[:50]:
            normalized = str(key).lower()
            if any(token in normalized for token in ("secret", "password", "private_key", "credential", "token", "key_material")):
                continue
            if isinstance(value, str):
                values.append(value[:400])
            elif isinstance(value, (int, float, bool)):
                values.append(str(value))
    return " ".join(values).lower()


def _incident_time(context: Mapping[str, Any]) -> Optional[datetime]:
    summary = context.get("summary") if isinstance(context.get("summary"), Mapping) else {}
    for value in (
        context.get("incident_start"),
        context.get("incident_time"),
        summary.get("incident_start"),
        summary.get("incident_time"),
    ):
        parsed = _parse_time(value)
        if parsed:
            return parsed
    return None


def _backup_rows(evidence: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        text = _text(item)
        raw = _raw(item)
        status = str(_field(item, ("status", "phase", "state", "result")) or "").lower()
        is_backup = any(token in text for token in ("backup", "snapshot", "velero")) or any(
            key in raw for key in ("backup_time", "backup_id", "snapshot_id")
        )
        if not is_backup:
            continue
        success = status in {"success", "succeeded", "completed", "complete", "ok"} or "backup succeeded" in text
        partial = status in {"partial", "partiallyfailed", "partially_failed"} or "partially failed" in text
        failed = status in {"failed", "error"} or "backup failed" in text
        stamp = _parse_time(_field(item, ("backup_time", "completion_time", "completed_at", "snapshot_time"))) or _timestamp(item)
        duration = _numeric(_field(item, ("duration_seconds", "backup_duration_seconds", "duration")))
        size = _numeric(_field(item, ("size_bytes", "backup_size_bytes", "size")))
        baseline_duration = _numeric(_field(item, ("baseline_duration_seconds", "duration_baseline", "normal_duration_seconds")))
        baseline_size = _numeric(_field(item, ("baseline_size_bytes", "size_baseline", "normal_size_bytes")))
        expected_interval = _numeric(_field(item, ("expected_schedule_seconds", "schedule_interval_seconds", "expected_interval_seconds")))
        retention = _numeric(_field(item, ("retention_count", "retention_days", "retention")))
        verified = bool(
            _bool(_field(item, ("verified", "integrity_verified", "restore_verified", "restore_test_success")))
            or "restore test succeeded" in text
            or "integrity verified" in text
        )
        usable = success and not partial and not failed and (
            verified or bool(_bool(_field(item, ("usable_restore_point", "restore_point_available"))))
        )
        rows.append({
            "evidence_id": _eid(item, index),
            "timestamp": stamp,
            "status": "partial" if partial else "failed" if failed else "success" if success else status or "unknown",
            "success": success and not partial and not failed,
            "partial": partial,
            "failed": failed,
            "duration_seconds": duration,
            "size_bytes": size,
            "baseline_duration_seconds": baseline_duration,
            "baseline_size_bytes": baseline_size,
            "expected_schedule_seconds": expected_interval,
            "retention": retention,
            "verified": verified,
            "usable": usable,
            "provider": str(_field(item, ("provider", "backup_system", "tool")) or item.get("source") or "unknown"),
            "coverage": _field(item, ("coverage", "covered_resources", "included_resources")),
            "offsite": _bool(_field(item, ("offsite", "secondary_copy", "remote_copy"))),
            "immutable": _bool(_field(item, ("immutable", "protected_copy", "object_lock"))),
        })
    rows.sort(key=lambda row: row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc))
    return rows


def _restore_rows(evidence: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        text = _text(item)
        if "restore" not in text and _field(item, ("restore_status", "restore_duration_seconds", "restore_point_time")) is None:
            continue
        status = str(_field(item, ("restore_status", "status", "phase", "result")) or "").lower()
        success = status in {"success", "succeeded", "completed", "complete", "ok"} or "restore test succeeded" in text
        failed = status in {"failed", "error"} or "restore failed" in text
        rows.append({
            "evidence_id": _eid(item, index),
            "timestamp": _parse_time(_field(item, ("restore_point_time", "backup_time", "snapshot_time"))) or _timestamp(item),
            "test_time": _parse_time(_field(item, ("restore_test_time", "tested_at", "completed_at"))) or _timestamp(item),
            "status": "success" if success and not failed else "failed" if failed else status or "unknown",
            "success": success and not failed,
            "duration_seconds": _numeric(_field(item, ("restore_duration_seconds", "duration_seconds", "duration"))),
            "failed_items": _numeric(_field(item, ("failed_items", "errors", "failed_count"))),
        })
    rows.sort(key=lambda row: row.get("test_time") or row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc))
    return rows


def _replication(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        name = str(item.get("name") or item.get("metric") or _field(item, ("name", "metric")) or "").lower()
        text = _text(item)
        if "replication" not in name and "replication" not in text and not any(token in text for token in ("wal continuity", "binlog continuity", "transaction log continuity")):
            continue
        lag = _numeric(item.get("value")) if "lag" in name else _numeric(_field(item, ("lag_seconds", "replication_lag_seconds")))
        state = str(_field(item, ("replication_state", "state", "status", "health")) or "").lower()
        healthy = _bool(_field(item, ("replication_healthy", "healthy", "connected")))
        if healthy is None and state:
            healthy = state in {"healthy", "streaming", "connected", "synced", "ok", "ready"}
            if state in {"failed", "broken", "disconnected", "stopped", "error", "unhealthy"}:
                healthy = False
        continuity = _bool(_field(item, ("wal_continuity", "binlog_continuity", "transaction_log_continuity", "log_continuity")))
        rows.append({
            "evidence_id": _eid(item, index),
            "timestamp": _timestamp(item),
            "lag_seconds": lag,
            "healthy": healthy,
            "state": state or "unknown",
            "log_continuity": continuity,
        })
    rows.sort(key=lambda row: row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc))
    latest = rows[-1] if rows else None
    return {
        "latest": latest,
        "history": rows[-12:],
        "healthy": latest.get("healthy") if latest else None,
        "lag_seconds": latest.get("lag_seconds") if latest else None,
        "log_continuity": latest.get("log_continuity") if latest else None,
        "evidence_ids": _unique(row["evidence_id"] for row in rows),
    }


def _kubernetes(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        text = _text(item)
        provider = str(_field(item, ("provider", "tool", "backup_system")) or "").lower()
        if "velero" not in text and "velero" not in provider and "backup cr" not in text:
            continue
        status = str(_field(item, ("phase", "status", "state")) or "").lower()
        failed_items = _numeric(_field(item, ("failed_items", "errors", "failed_count"))) or 0.0
        pv_expected = _numeric(_field(item, ("pv_expected", "persistent_volumes_expected", "snapshot_expected")))
        pv_backed = _numeric(_field(item, ("pv_backed_up", "persistent_volumes_backed_up", "snapshots_completed")))
        coverage = None
        if pv_expected not in (None, 0):
            coverage = max(0.0, min(1.0, float(pv_backed or 0) / float(pv_expected)))
        partial = status in {"partiallyfailed", "partially_failed", "partial"} or failed_items > 0 or (coverage is not None and coverage < 1.0)
        rows.append({
            "evidence_id": _eid(item, index),
            "timestamp": _timestamp(item),
            "status": status or "unknown",
            "failed_items": int(failed_items),
            "pv_expected": pv_expected,
            "pv_backed_up": pv_backed,
            "pv_coverage": coverage,
            "partial": partial,
        })
    return {
        "records": rows[-12:],
        "partial_backups": [row for row in rows if row["partial"]],
        "evidence_ids": _unique(row["evidence_id"] for row in rows),
    }


def _encryption(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    encrypted = False
    key_available: Optional[bool] = None
    evidence_ids: List[str] = []
    for index, item in enumerate(evidence):
        text = _text(item)
        if "encrypt" not in text and _field(item, ("encrypted", "encryption_enabled", "key_available", "kms_key_available")) is None:
            continue
        encrypted_value = _bool(_field(item, ("encrypted", "encryption_enabled")))
        if encrypted_value is True or "encrypted" in text:
            encrypted = True
        available = _bool(_field(item, ("key_available", "kms_key_available", "encryption_key_available")))
        if available is not None:
            key_available = available
        evidence_ids.append(_eid(item, index))
    return {
        "encrypted": encrypted,
        "key_available": key_available,
        "metadata_only": True,
        "evidence_ids": _unique(evidence_ids),
        "policy": "never expose encryption key material; only availability metadata is analyzed",
    }


def _schedule(backup_rows: List[Dict[str, Any]], reference_time: Optional[datetime]) -> Dict[str, Any]:
    successful = [row for row in backup_rows if row["success"] and row.get("timestamp")]
    latest = successful[-1] if successful else None
    expected = next((row["expected_schedule_seconds"] for row in reversed(backup_rows) if row.get("expected_schedule_seconds")), None)
    age = None
    freshness = "unknown"
    missed = None
    if latest and reference_time and reference_time >= latest["timestamp"]:
        age = (reference_time - latest["timestamp"]).total_seconds()
        if expected:
            missed = max(0, int(age // expected) - 1)
            freshness = "fresh" if age <= expected * 1.25 else "stale"
        else:
            freshness = "observed_but_schedule_unknown"
    duration_anomaly = None
    size_anomaly = None
    if latest:
        duration = latest.get("duration_seconds")
        baseline_duration = latest.get("baseline_duration_seconds")
        if duration is not None and baseline_duration not in (None, 0):
            duration_anomaly = round(duration / baseline_duration, 4)
        size = latest.get("size_bytes")
        baseline_size = latest.get("baseline_size_bytes")
        if size is not None and baseline_size not in (None, 0):
            size_anomaly = round(size / baseline_size, 4)
    return {
        "latest_successful_backup": latest,
        "backup_age_seconds": None if age is None else int(age),
        "expected_schedule_seconds": expected,
        "missed_backups_estimate": missed,
        "freshness": freshness,
        "duration_ratio_to_baseline": duration_anomaly,
        "size_ratio_to_baseline": size_anomaly,
    }


def _verified_point(backup_rows: List[Dict[str, Any]], restore_rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for row in backup_rows:
        if row["usable"] and row.get("timestamp"):
            candidates.append({
                "timestamp": row["timestamp"],
                "evidence_ids": [row["evidence_id"]],
                "basis": "verified_backup_or_snapshot",
            })
    for row in restore_rows:
        if row["success"] and row.get("timestamp"):
            candidates.append({
                "timestamp": row["timestamp"],
                "evidence_ids": [row["evidence_id"]],
                "basis": "successful_restore_test",
            })
    candidates.sort(key=lambda row: row["timestamp"])
    return candidates[-1] if candidates else None


def build_recovery_readiness_analysis(
    evidence: List[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    live = [item for item in evidence if isinstance(item, Mapping)]
    context = context or {}
    incident = _incident_time(context)
    backups = _backup_rows(live)
    restores = _restore_rows(live)
    replication = _replication(live)
    kubernetes = _kubernetes(live)
    encryption = _encryption(live)
    observed_times = [time for time in (_timestamp(item) for item in live) if time]
    reference_time = incident or (max(observed_times) if observed_times else datetime.now(timezone.utc))
    schedule = _schedule(backups, reference_time)
    latest_backup = schedule["latest_successful_backup"]
    verified = _verified_point(backups, restores)

    rpo_target = _numeric(context.get("rpo_seconds"))
    if rpo_target is None:
        rpo_target = next((_numeric(_field(item, ("rpo_seconds", "rpo_target_seconds"))) for item in live if _numeric(_field(item, ("rpo_seconds", "rpo_target_seconds"))) is not None), None)
    data_loss_seconds = None
    if incident and verified and incident >= verified["timestamp"]:
        data_loss_seconds = int((incident - verified["timestamp"]).total_seconds())
    rpo_status = "unknown"
    if data_loss_seconds is not None and rpo_target is not None:
        rpo_status = "compliant" if data_loss_seconds <= rpo_target else "non_compliant"
    elif data_loss_seconds is not None:
        rpo_status = "measurable_target_unknown"
    elif incident and not verified:
        rpo_status = "not_demonstrated"

    rto_target = _numeric(context.get("rto_seconds"))
    if rto_target is None:
        rto_target = next((_numeric(_field(item, ("rto_seconds", "rto_target_seconds"))) for item in live if _numeric(_field(item, ("rto_seconds", "rto_target_seconds"))) is not None), None)
    successful_restores = [row for row in restores if row["success"]]
    latest_restore_test = successful_restores[-1] if successful_restores else None
    restore_validation_status = "verified" if latest_restore_test or verified else "untested"
    if latest_restore_test and latest_restore_test.get("duration_seconds") is not None and rto_target is not None:
        rto_risk = "low" if latest_restore_test["duration_seconds"] <= rto_target else "high"
    elif latest_restore_test:
        rto_risk = "moderate_target_unknown"
    else:
        rto_risk = "high_restore_untested"

    coverage_gaps: List[str] = []
    if not latest_backup:
        coverage_gaps.append("successful backup evidence")
    if not verified:
        coverage_gaps.append("verified usable restore point")
    if schedule["expected_schedule_seconds"] is None:
        coverage_gaps.append("expected backup schedule")
    if schedule["freshness"] == "stale":
        coverage_gaps.append("fresh backup within expected schedule")
    if kubernetes["partial_backups"]:
        coverage_gaps.append("complete Kubernetes/PV snapshot coverage")
    if replication["healthy"] is False:
        coverage_gaps.append("healthy replication")
    if replication["log_continuity"] is False:
        coverage_gaps.append("continuous WAL/binlog/transaction-log chain")
    if encryption["encrypted"] and encryption["key_available"] is not True:
        coverage_gaps.append("encryption-key availability metadata")
    if not any(row.get("offsite") is True for row in backups):
        coverage_gaps.append("offsite/secondary recovery copy evidence")
    if not any(row.get("immutable") is True for row in backups):
        coverage_gaps.append("immutable/protected recovery copy evidence")

    confidence_ceiling = 0.90
    confidence_reasons: List[str] = []
    if not successful_restores:
        confidence_ceiling = min(confidence_ceiling, 0.55)
        confidence_reasons.append("restore has not been successfully tested")
    if not verified:
        confidence_ceiling = min(confidence_ceiling, 0.45)
        confidence_reasons.append("no verified usable restore point")
    if replication["healthy"] is False:
        confidence_ceiling = min(confidence_ceiling, 0.60)
        confidence_reasons.append("replication is unhealthy")
    if kubernetes["partial_backups"]:
        confidence_ceiling = min(confidence_ceiling, 0.60)
        confidence_reasons.append("Kubernetes/PV backup is partial")

    latest_backup_payload = None
    if latest_backup:
        latest_backup_payload = {
            "timestamp": _iso(latest_backup["timestamp"]),
            "evidence_id": latest_backup["evidence_id"],
            "provider": latest_backup["provider"],
            "duration_seconds": latest_backup["duration_seconds"],
            "size_bytes": latest_backup["size_bytes"],
            "verified": latest_backup["verified"],
        }
    latest_verified_payload = None
    if verified:
        latest_verified_payload = {
            "timestamp": _iso(verified["timestamp"]),
            "evidence_ids": verified["evidence_ids"],
            "basis": verified["basis"],
        }

    sequence = ["storage", "database", "core_dependency", "application"]
    graph = {
        "directed": True,
        "nodes": sequence,
        "edges": [
            {"from": "storage", "to": "database"},
            {"from": "database", "to": "core_dependency"},
            {"from": "core_dependency", "to": "application"},
        ],
        "policy": "recover lower-level stateful dependencies before higher-level application services unless an approved runbook proves a different order",
    }

    risks: List[Dict[str, Any]] = []
    if schedule["freshness"] == "stale":
        risks.append({"risk": "stale_backup", "evidence_ids": [latest_backup["evidence_id"]] if latest_backup else []})
    if replication["healthy"] is False:
        risks.append({"risk": "broken_replication", "evidence_ids": replication["evidence_ids"]})
    if kubernetes["partial_backups"]:
        risks.append({"risk": "partial_kubernetes_backup", "evidence_ids": kubernetes["evidence_ids"]})
    if encryption["encrypted"] and encryption["key_available"] is not True:
        risks.append({"risk": "encryption_key_availability_unproven", "evidence_ids": encryption["evidence_ids"]})
    if not successful_restores:
        risks.append({"risk": "restore_untested", "evidence_ids": []})

    missing = [{"evidence": gap, "information_gain": max(0.5, 1.0 - index * 0.06)} for index, gap in enumerate(coverage_gaps[:8])]

    return {
        "policy": "backup_success_is_not_recoverability; only_verified_usable_restore_evidence_supports_high_recoverability_confidence",
        "service": service_name,
        "latest_backup": latest_backup_payload,
        "latest_verified_restore_point": latest_verified_payload,
        "backup_freshness": schedule,
        "backup_history": backups[-20:],
        "restore_history": restores[-20:],
        "replication": replication,
        "kubernetes_velero": kubernetes,
        "encryption": encryption,
        "potential_data_loss_window_seconds": data_loss_seconds,
        "rpo_target_seconds": rpo_target,
        "rpo_status": rpo_status,
        "rto_target_seconds": rto_target,
        "rto_risk": rto_risk,
        "coverage_gaps": _unique(coverage_gaps, 20),
        "restore_validation_status": restore_validation_status,
        "recovery_sequence": sequence,
        "recovery_dependency_graph": graph,
        "risk_signals": risks,
        "human_decision_required": True,
        "confidence_ceiling": confidence_ceiling,
        "explainable_confidence": {
            "ceiling": confidence_ceiling,
            "reasons": confidence_reasons or ["verified restore evidence and no major readiness contradiction observed"],
        },
        "next_best_evidence": missing,
        "execution_boundary": "analysis_only_no_restore_or_failover",
    }
