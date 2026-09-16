from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


CHANGE_TOKENS = {
    "deployment": ("deploy", "deployment", "release", "rollout"),
    "config": ("config", "configuration", "environment variable", "env var", "config hash"),
    "feature_flag": ("feature flag", "flag change", "feature_flag"),
    "dependency_version": ("dependency version", "library version", "dependency_version"),
    "infrastructure": ("infrastructure change", "terraform", "network change", "node change", "host change"),
    "build": ("jenkins", "build", "pipeline"),
    "kubernetes_rollout": ("kubernetes rollout", "replicaset", "image digest", "image_digest"),
    "migration": ("schema migration", "migration", "alembic"),
}

METRIC_GROUPS = {
    "error_rate": ("error_rate", "errors", "5xx", "failure_rate"),
    "latency": ("latency", "duration", "p95", "p99", "response_time"),
    "traffic": ("traffic", "request_rate", "requests", "rps", "throughput"),
    "resource_use": ("cpu", "memory", "rss", "iowait", "utilization", "saturation"),
    "dependency_behavior": ("dependency", "upstream", "downstream", "external_latency", "dependency_error"),
    "slo": ("slo", "error_budget", "availability", "success_rate"),
}

ALT_TOKENS = {
    "dependency_outage": ("dependency outage", "upstream outage", "downstream outage", "dependency unavailable"),
    "infrastructure_fault": ("cpu saturation", "memory pressure", "node failure", "host failure", "infrastructure fault"),
    "network_fault": ("packet loss", "dns failure", "route failure", "network outage", "connection reset"),
    "storage_fault": ("storage latency", "disk error", "io error", "i/o error", "filesystem error"),
    "database_fault": ("deadlock", "replication lag", "database outage", "db outage", "connection exhaustion"),
}


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _lookup(item: Mapping[str, Any], *keys: str) -> Any:
    raw = _raw(item)
    labels = raw.get("labels") if isinstance(raw.get("labels"), Mapping) else {}
    for source in (raw, labels, item):
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
    for value in (
        item.get("observed_at"), item.get("timestamp"), item.get("created_at"),
        _lookup(item, "@timestamp", "timestamp", "time", "changed_at", "deployed_at"),
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


def _text(item: Mapping[str, Any]) -> str:
    return " ".join(str(x) for x in (
        item.get("name"), item.get("message"), item.get("value"), _raw(item)
    ) if x not in (None, "")).lower()


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _metric_group(item: Mapping[str, Any]) -> Optional[str]:
    name = _norm(item.get("name") or item.get("metric") or _lookup(item, "metric", "item_key"))
    text = _text(item)
    for group, tokens in METRIC_GROUPS.items():
        if any(_norm(token) in name or token in text for token in tokens):
            return group
    return None


def _metric_value(item: Mapping[str, Any]) -> Optional[float]:
    value = item.get("value") if item.get("value") is not None else _lookup(item, "value", "current", "current_value")
    return _number(value)


def _change_type(item: Mapping[str, Any]) -> Optional[str]:
    diagnostic = _norm(_lookup(item, "diagnostic", "kind", "subtype", "event_type", "change_type"))
    text = _text(item)
    for change_type, tokens in CHANGE_TOKENS.items():
        if any(_norm(token) in diagnostic or token in text for token in tokens):
            return change_type
    if str(item.get("type", "")).lower() == "change":
        return diagnostic or "change"
    return None


def _change_record(item: Mapping[str, Any], index: int) -> Optional[Dict[str, Any]]:
    change_type = _change_type(item)
    if not change_type:
        return None
    stamp = _timestamp(item)
    return {
        "change_id": _eid(item, index),
        "change_type": change_type,
        "timestamp": stamp.isoformat() if stamp else None,
        "service": _lookup(item, "service", "service_name", "application"),
        "environment": _lookup(item, "environment", "env", "namespace", "cluster"),
        "target": _lookup(item, "target", "workload", "deployment", "component"),
        "version": _lookup(item, "release", "version", "release_version", "app_version"),
        "image_digest": _lookup(item, "image_digest", "digest", "container_image"),
        "config_hash": _lookup(item, "config_hash", "environment_hash", "env_hash"),
        "feature_flag": _lookup(item, "feature_flag", "flag", "flag_name"),
        "dependency_version": _lookup(item, "dependency_version", "dependency", "library_version"),
        "build_result": _lookup(item, "build_result", "jenkins_result", "pipeline_result", "deploy_result"),
        "rollout_status": _lookup(item, "rollout_status", "deployment_status"),
        "replica_transition": _lookup(item, "replica_transition", "replicas", "replica_change"),
        "restart_caused_by_release": _lookup(item, "restart_caused_by_release", "release_restart", "restarted_by_rollout"),
        "migration": _lookup(item, "migration", "schema_migration", "revision"),
        "instances": _as_list(_lookup(item, "instances", "pods", "replicas", "affected_instances")),
        "endpoints": _as_list(_lookup(item, "endpoints", "affected_endpoints", "routes")),
    }


def _as_list(value: Any) -> List[str]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(x) for x in value if x not in (None, "")]
    text = str(value)
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text]


def _incident_start(context: Mapping[str, Any]) -> Optional[datetime]:
    return _parse_time(context.get("incident_start") or context.get("started_at") or (context.get("time_range") or {}).get("start") if isinstance(context.get("time_range"), Mapping) else None)


def _temporal_score(change_time: Optional[datetime], incident_time: Optional[datetime]) -> Tuple[float, Optional[float]]:
    if not change_time or not incident_time:
        return 0.30, None
    delta = (incident_time - change_time).total_seconds()
    if delta < -300:
        return 0.05, delta
    minutes = abs(delta) / 60.0
    if minutes <= 5:
        return 1.0, delta
    if minutes <= 15:
        return 0.88, delta
    if minutes <= 30:
        return 0.68, delta
    if minutes <= 60:
        return 0.42, delta
    if minutes <= 180:
        return 0.20, delta
    return 0.05, delta


def _scope_values(item: Mapping[str, Any]) -> set[str]:
    values: List[str] = []
    for key in ("service", "service_name", "application", "environment", "env", "namespace", "cluster", "target", "workload", "deployment", "component", "instance", "pod", "endpoint", "route", "version", "release"):
        value = _lookup(item, key)
        values.extend(_as_list(value))
    return {_norm(v) for v in values if v}


def _change_scope(change: Mapping[str, Any]) -> set[str]:
    values: List[str] = []
    for key in ("service", "environment", "target", "version"):
        values.extend(_as_list(change.get(key)))
    values.extend(change.get("instances") or [])
    values.extend(change.get("endpoints") or [])
    return {_norm(v) for v in values if v}


def _window_label(item: Mapping[str, Any], change_time: Optional[datetime], window_seconds: int) -> Optional[str]:
    explicit = _norm(_lookup(item, "window", "phase", "period"))
    if explicit in {"before", "pre", "baseline", "stable"}:
        return "before"
    if explicit in {"after", "post", "incident", "canary", "new"}:
        return "after"
    stamp = _timestamp(item)
    if not stamp or not change_time:
        return None
    delta = (stamp - change_time).total_seconds()
    if -window_seconds <= delta < 0:
        return "before"
    if 0 <= delta <= window_seconds:
        return "after"
    return None


def _before_after(change: Mapping[str, Any], metric_items: Sequence[Mapping[str, Any]], window_seconds: int) -> Tuple[List[Dict[str, Any]], float]:
    change_time = _parse_time(change.get("timestamp"))
    grouped: Dict[str, Dict[str, List[Tuple[str, float]]]] = {}
    after_scopes: List[set[str]] = []
    for index, item in enumerate(metric_items):
        group = _metric_group(item)
        value = _metric_value(item)
        label = _window_label(item, change_time, window_seconds)
        if not group or value is None or not label:
            continue
        grouped.setdefault(group, {"before": [], "after": []})[label].append((_eid(item, index), value))
        if label == "after":
            after_scopes.append(_scope_values(item))

    rows: List[Dict[str, Any]] = []
    worsening_components: List[float] = []
    for group, windows in grouped.items():
        before = [v for _, v in windows["before"]]
        after = [v for _, v in windows["after"]]
        if not before or not after:
            continue
        before_avg = mean(before)
        after_avg = mean(after)
        absolute = after_avg - before_avg
        relative = absolute / max(abs(before_avg), 1e-9)
        if group == "slo":
            worse = max(0.0, -relative)
        elif group == "traffic":
            worse = min(1.0, abs(relative)) if abs(relative) >= 0.25 else 0.0
        else:
            worse = max(0.0, relative)
        worsening_components.append(min(1.0, worse))
        rows.append({
            "metric": group,
            "before": before_avg,
            "after": after_avg,
            "absolute_delta": absolute,
            "relative_delta": relative,
            "evidence_ids": [eid for eid, _ in windows["before"] + windows["after"]][:20],
        })
    delta_score = mean(worsening_components) if worsening_components else 0.0
    return rows, delta_score


def _scope_overlap_score(change: Mapping[str, Any], metric_items: Sequence[Mapping[str, Any]], change_time: Optional[datetime], window_seconds: int) -> Tuple[float, List[str]]:
    cscope = _change_scope(change)
    if not cscope:
        return 0.35, []
    observed: set[str] = set()
    for item in metric_items:
        if _window_label(item, change_time, window_seconds) == "after":
            observed.update(_scope_values(item))
    if not observed:
        return 0.30, []
    overlap = sorted(cscope & observed)
    if overlap:
        return min(1.0, 0.55 + 0.15 * len(overlap)), overlap
    return 0.05, []


def _comparison_score(metric_items: Sequence[Mapping[str, Any]], change: Mapping[str, Any], change_time: Optional[datetime], window_seconds: int) -> Tuple[float, Dict[str, Any], List[str]]:
    new_values: Dict[str, List[float]] = {}
    stable_values: Dict[str, List[float]] = {}
    all_versions: set[str] = set()
    evidence_ids: List[str] = []
    for index, item in enumerate(metric_items):
        if _window_label(item, change_time, window_seconds) != "after":
            continue
        group = _metric_group(item)
        value = _metric_value(item)
        if not group or value is None or group not in {"error_rate", "latency", "slo", "resource_use"}:
            continue
        role = _norm(_lookup(item, "role", "track", "variant", "cohort", "release_channel"))
        version = str(_lookup(item, "version", "release", "app_version") or "")
        if version:
            all_versions.add(version)
        change_version = str(change.get("version") or "")
        is_new = role in {"canary", "new", "candidate"} or (change_version and version == change_version)
        is_stable = role in {"stable", "baseline", "old", "control"} or (change_version and version and version != change_version)
        if is_new:
            new_values.setdefault(group, []).append(value)
            evidence_ids.append(_eid(item, index))
        elif is_stable:
            stable_values.setdefault(group, []).append(value)
            evidence_ids.append(_eid(item, index))

    comparisons: List[Dict[str, Any]] = []
    advantages: List[float] = []
    all_bad = False
    for group in sorted(set(new_values) & set(stable_values)):
        new = mean(new_values[group])
        stable = mean(stable_values[group])
        if group == "slo":
            degradation = max(0.0, (stable - new) / max(abs(stable), 1e-9))
        else:
            degradation = max(0.0, (new - stable) / max(abs(stable), 1e-9))
        advantages.append(min(1.0, degradation))
        comparisons.append({"metric": group, "new_or_canary": new, "stable": stable, "relative_degradation": degradation})
        if group in {"error_rate", "latency"} and new > 0 and stable > 0 and degradation < 0.15:
            all_bad = True
    score = mean(advantages) if advantages else 0.0
    if score >= 0.25:
        score = min(1.0, 0.45 + score)
    return score, {"comparisons": comparisons, "versions_observed": sorted(all_versions), "all_versions_similarly_affected": all_bad and bool(comparisons)}, list(dict.fromkeys(evidence_ids))[:20]


def _alternatives(items: Sequence[Mapping[str, Any]], incident_time: Optional[datetime], window_seconds: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        text = _text(item)
        stamp = _timestamp(item)
        if incident_time and stamp and abs((stamp - incident_time).total_seconds()) > max(window_seconds * 2, 1800):
            continue
        for code, tokens in ALT_TOKENS.items():
            if any(token in text for token in tokens):
                rows.append({"cause": code, "evidence_id": _eid(item, index), "timestamp": stamp.isoformat() if stamp else None})
                break
    dedup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        dedup[(row["cause"], row["evidence_id"])] = row
    return list(dedup.values())[:20]


def _change_quality(change: Mapping[str, Any]) -> float:
    score = 0.4
    if change.get("version") or change.get("image_digest") or change.get("config_hash") or change.get("migration"):
        score += 0.25
    result = _norm(change.get("build_result"))
    rollout = _norm(change.get("rollout_status"))
    if result in {"success", "successful", "passed", "deployed"} or rollout in {"complete", "completed", "success", "progressing"}:
        score += 0.20
    if change.get("restart_caused_by_release") not in (None, "", False):
        score += 0.10
    return min(1.0, score)


def _simultaneous(changes: Sequence[Mapping[str, Any]], tolerance_seconds: int = 180) -> List[List[str]]:
    groups: List[List[str]] = []
    used: set[str] = set()
    for change in changes:
        cid = str(change["change_id"])
        if cid in used:
            continue
        ts = _parse_time(change.get("timestamp"))
        if not ts:
            continue
        group = [cid]
        for other in changes:
            oid = str(other["change_id"])
            if oid == cid or oid in used:
                continue
            ots = _parse_time(other.get("timestamp"))
            if ots and abs((ots - ts).total_seconds()) <= tolerance_seconds:
                group.append(oid)
        if len(group) > 1:
            groups.append(group)
            used.update(group)
    return groups


def build_change_correlation_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    ctx = context if isinstance(context, Mapping) else {}
    incident_time = _incident_start(ctx)
    window_minutes = int(_number(ctx.get("change_window_minutes")) or 15)
    window_seconds = max(300, min(window_minutes * 60, 7200))
    changes = [row for i, item in enumerate(items) if (row := _change_record(item, i))]
    metric_items = [item for item in items if _metric_group(item) is not None]
    alternatives = _alternatives(items, incident_time, window_seconds)
    simultaneous = _simultaneous(changes)

    candidates: List[Dict[str, Any]] = []
    all_deltas: List[Dict[str, Any]] = []
    rollback: List[Dict[str, Any]] = []
    for change in changes:
        change_time = _parse_time(change.get("timestamp"))
        temporal, temporal_delta_seconds = _temporal_score(change_time, incident_time)
        deltas, metric_delta = _before_after(change, metric_items, window_seconds)
        scope_score, overlap = _scope_overlap_score(change, metric_items, change_time, window_seconds)
        comparison_score, comparison, comparison_eids = _comparison_score(metric_items, change, change_time, window_seconds)
        quality = _change_quality(change)

        conflict_reasons: List[str] = []
        if not deltas:
            conflict_reasons.append("no_measured_before_after_delta")
        elif metric_delta < 0.10:
            conflict_reasons.append("post_change_metrics_do_not_materially_worsen")
        if _change_scope(change) and scope_score <= 0.05:
            conflict_reasons.append("affected_scope_does_not_overlap_change_scope")
        if comparison.get("all_versions_similarly_affected"):
            conflict_reasons.append("stable_and_new_versions_are_similarly_affected")

        related_alt = alternatives
        alt_penalty = min(0.28, 0.10 * len({row["cause"] for row in related_alt}))
        conflict_penalty = min(0.30, 0.10 * len(conflict_reasons))
        reproducibility = comparison_score
        baseline_score = comparison_score if comparison.get("comparisons") else (0.45 if deltas else 0.0)
        positive = (
            0.18 * temporal
            + 0.26 * min(1.0, metric_delta)
            + 0.18 * scope_score
            + 0.14 * reproducibility
            + 0.12 * baseline_score
            + 0.12 * quality
        )
        score = max(0.0, min(1.0, positive - alt_penalty - conflict_penalty))
        if comparison_score >= 0.60 and not comparison.get("all_versions_similarly_affected"):
            score = min(1.0, score + 0.10)

        role = "causal_candidate"
        if score < 0.35:
            role = "weak_or_unrelated_change"
        elif score < 0.65:
            role = "correlated_change_requires_falsification"
        candidate = {
            **change,
            "change_correlation_score": round(score, 4),
            "causal_role": role,
            "root_cause_status": "candidate_requires_falsification",
            "score_factors": {
                "temporal_proximity": round(temporal, 4),
                "metric_log_delta": round(min(1.0, metric_delta), 4),
                "affected_scope_overlap": round(scope_score, 4),
                "reproducibility_instance_comparison": round(reproducibility, 4),
                "baseline_canary_comparison": round(baseline_score, 4),
                "change_evidence_quality": round(quality, 4),
                "alternative_explanation_penalty": round(alt_penalty, 4),
                "conflicting_evidence_penalty": round(conflict_penalty, 4),
            },
            "temporal_delta_seconds_change_to_incident": temporal_delta_seconds,
            "scope_overlap": overlap,
            "instance_version_comparison": comparison,
            "comparison_evidence_ids": comparison_eids,
            "conflicting_evidence": conflict_reasons,
            "before_after_deltas": deltas,
            "expected_falsification_result": "If stable/control instances fail equally, post-change metrics do not regress, or the affected scope does not overlap the change, change causality should weaken.",
        }
        candidates.append(candidate)
        for delta in deltas:
            all_deltas.append({"change_id": change["change_id"], **delta})
        if score >= 0.65 and deltas and not comparison.get("all_versions_similarly_affected"):
            rollback.append({
                "change_id": change["change_id"],
                "score": round(score, 4),
                "evidence": [
                    "measured post-change regression",
                    "scope/version comparison supports the change candidate" if comparison.get("comparisons") else "before/after regression supports the change candidate",
                ],
                "policy": "rollback_candidate_only_never_execute_without_approval",
            })

    candidates.sort(key=lambda row: float(row["change_correlation_score"]), reverse=True)
    overall = float(candidates[0]["change_correlation_score"]) if candidates else 0.0
    all_versions_bad = any((row.get("instance_version_comparison") or {}).get("all_versions_similarly_affected") for row in candidates)
    if all_versions_bad:
        for cause in ("dependency_outage", "infrastructure_fault"):
            if not any(row["cause"] == cause for row in alternatives):
                alternatives.append({"cause": cause, "evidence_id": None, "timestamp": None, "reason": "stable and changed versions are affected together; verify shared dependency/infrastructure"})

    gaps: List[Dict[str, Any]] = []
    if not changes:
        gaps.append({"evidence": "deployment/config/flag/dependency/infrastructure/migration change events", "information_gain": 1.0})
    if changes and not all_deltas:
        gaps.append({"evidence": "before/after error, latency, traffic, resource, dependency and SLO metrics", "information_gain": 0.98})
    if changes and not any((row.get("instance_version_comparison") or {}).get("comparisons") for row in candidates):
        gaps.append({"evidence": "new/canary versus stable replica or instance metrics", "information_gain": 0.94})
    if changes and not any(row.get("scope_overlap") for row in candidates):
        gaps.append({"evidence": "affected instance/endpoint scope aligned to each change", "information_gain": 0.90})

    return {
        "policy": "a nearby change is not causal by timing alone; scores require measured regression, scope/reproducibility evidence, and explicit alternatives/conflicts",
        "service": service_name,
        "candidate_changes": candidates[:20],
        "change_correlation_score": round(overall, 4),
        "before_after_deltas": all_deltas[:80],
        "alternative_causes": alternatives[:20],
        "rollback_candidate_evidence": rollback[:10],
        "simultaneous_changes": simultaneous,
        "next_best_evidence": sorted(gaps, key=lambda row: float(row["information_gain"]), reverse=True)[:10],
        "analysis_stages": [
            "change_event_normalization",
            "before_after_window_construction",
            "metric_and_log_delta_comparison",
            "affected_scope_overlap",
            "instance_and_version_reproducibility",
            "baseline_canary_stable_comparison",
            "alternative_and_conflicting_evidence",
            "causal_score_and_rollback_candidate_evidence",
            "llm_synthesis_bounded_by_deterministic_correlation",
        ],
        "execution_boundary": "analysis_only_no_rollback_execution",
    }
