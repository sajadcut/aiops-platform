from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SENSITIVE_TOKENS = (
    "authorization", "password", "passwd", "secret", "private_key", "privatekey",
    "access_token", "refresh_token", "id_token", "client_secret", "api_key", "apikey",
    "credential", "cookie", "set-cookie",
)

LATENCY_PERCENTILES = ("p50", "p90", "p95", "p99")


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


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
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        candidate = value.strip().lower().replace(",", "")
        multiplier = 1.0
        if candidate.endswith("ms"):
            candidate = candidate[:-2].strip()
        elif candidate.endswith("s") and re.fullmatch(r"[-+]?\d+(?:\.\d+)?s", candidate):
            candidate = candidate[:-1]
            multiplier = 1000.0
        if candidate.endswith("%"):
            candidate = candidate[:-1].strip()
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


def _first(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _labels(item: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = _raw(item)
    labels = raw.get("labels") or raw.get("attributes") or raw.get("resource") or {}
    return labels if isinstance(labels, Mapping) else {}


def _field(item: Mapping[str, Any], keys: Sequence[str]) -> Any:
    value = _first(item, keys)
    if value not in (None, ""):
        return value
    raw = _raw(item)
    value = _first(raw, keys)
    if value not in (None, ""):
        return value
    labels = _labels(item)
    return _first(labels, keys)


def _metric_name(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    value = item.get("name") or item.get("metric") or raw.get("name") or raw.get("metric") or raw.get("item_key") or ""
    return str(value).strip().lower()


def _metric_value(item: Mapping[str, Any]) -> Optional[float]:
    raw = _raw(item)
    value = item.get("value") if item.get("value") is not None else _first(raw, ("value", "current", "latest"))
    return _numeric(value)


def _baseline(item: Mapping[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    raw = _raw(item)
    for key in (
        "baseline", "baseline_value", "pre_incident", "pre_incident_value", "previous",
        "previous_value", "historical", "historical_normal", "normal", "normal_value",
    ):
        value = _numeric(raw.get(key))
        if value is not None:
            return value, key
    return None, None


def _delta(current: Optional[float], baseline: Optional[float]) -> Dict[str, Optional[float]]:
    if current is None or baseline is None:
        return {"absolute": None, "relative": None}
    absolute = current - baseline
    relative = None if baseline == 0 else absolute / abs(baseline)
    return {
        "absolute": round(absolute, 6),
        "relative": None if relative is None else round(relative, 4),
    }


def _classify_metric(name: str) -> Optional[str]:
    normalized = name.lower()
    if any(token in normalized for token in ("request_rate", "requests_per_second", "request_count", "http_requests", "rps", "qps", "throughput")):
        return "request_rate"
    if any(token in normalized for token in ("error_rate", "errors_per_second", "5xx_rate", "http_5xx", "failed_requests", "failure_rate")):
        return "error_rate"
    if any(token in normalized for token in ("latency", "duration", "response_time", "request_time")):
        return "latency"
    if any(token in normalized for token in ("retry", "retries")):
        return "retry"
    if any(token in normalized for token in ("thread_pool", "worker_pool", "active_workers", "busy_workers", "worker_queue")):
        return "thread_pool"
    if any(token in normalized for token in ("connection_pool", "db_pool", "pool_active", "pool_wait", "pool_exhaust")):
        return "connection_pool"
    if any(token in normalized for token in ("gc_", "garbage_collection", "heap", "memory", "rss", "working_set")):
        return "memory_gc"
    if any(token in normalized for token in ("cpu", "process_cpu")):
        return "cpu"
    if any(token in normalized for token in ("file_descriptor", "fd_", "open_fds", "socket", "connections_open")):
        return "fd_socket"
    if any(token in normalized for token in ("queue", "backpressure", "backlog", "pending_work")):
        return "queue_backpressure"
    if any(token in normalized for token in ("slo", "error_budget", "burn_rate", "availability")):
        return "slo"
    return None


def _percentile(name: str, item: Mapping[str, Any]) -> Optional[str]:
    text = " ".join((name, str(_field(item, ("quantile", "percentile", "le")) or ""))).lower()
    aliases = {
        "p50": ("p50", "0.5", "50th"),
        "p90": ("p90", "0.9", "90th"),
        "p95": ("p95", "0.95", "95th"),
        "p99": ("p99", "0.99", "99th"),
    }
    for percentile, tokens in aliases.items():
        if any(token in text for token in tokens):
            return percentile
    return None


def _metric_features(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    observations: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    percentiles: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for index, item in enumerate(evidence):
        if str(item.get("type") or "").lower() != "metric":
            continue
        name = _metric_name(item)
        kind = _classify_metric(name)
        current = _metric_value(item)
        baseline, baseline_kind = _baseline(item)
        if not kind and current is None:
            continue
        row = {
            "evidence_id": _evidence_id(item, index),
            "metric": name or "unnamed",
            "current": current,
            "baseline": baseline,
            "baseline_kind": baseline_kind,
            "delta": _delta(current, baseline),
            "timestamp": str(item.get("observed_at") or item.get("timestamp") or item.get("created_at") or "") or None,
            "endpoint": _field(item, ("endpoint", "route", "path", "http.route", "url")),
            "region": _field(item, ("region", "zone", "availability_zone")),
            "instance": _field(item, ("instance", "host", "hostname", "pod")),
        }
        if kind:
            observations[kind].append(row)
        if kind == "latency":
            percentile = _percentile(name, item)
            if percentile:
                percentiles[percentile].append(row)

    largest_deltas = []
    for kind, rows in observations.items():
        for row in rows:
            relative = row["delta"].get("relative")
            if relative is not None:
                largest_deltas.append({"kind": kind, **row})
    largest_deltas.sort(key=lambda row: abs(float(row["delta"]["relative"] or 0)), reverse=True)

    return {
        "red": {
            "request_rate": observations.get("request_rate", [])[:10],
            "error_rate": observations.get("error_rate", [])[:10],
            "duration_latency": observations.get("latency", [])[:16],
        },
        "latency_percentiles": {key: percentiles.get(key, [])[:8] for key in LATENCY_PERCENTILES},
        "tail_latency_present": bool(percentiles.get("p95") or percentiles.get("p99")),
        "resource_pressure": {
            "thread_pool": observations.get("thread_pool", [])[:8],
            "connection_pool": observations.get("connection_pool", [])[:8],
            "memory_gc": observations.get("memory_gc", [])[:8],
            "cpu": observations.get("cpu", [])[:8],
            "fd_socket": observations.get("fd_socket", [])[:8],
            "queue_backpressure": observations.get("queue_backpressure", [])[:8],
        },
        "retry_metrics": observations.get("retry", [])[:8],
        "slo_signals": observations.get("slo", [])[:8],
        "largest_baseline_deltas": largest_deltas[:16],
    }


def _status_family(value: Any) -> Optional[str]:
    try:
        code = int(str(value).split(".", 1)[0])
    except (TypeError, ValueError):
        return None
    if 100 <= code <= 599:
        return f"{code // 100}xx"
    return None


def _http_features(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    families: Counter[str] = Counter()
    endpoints: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "families": Counter(), "evidence_ids": []})
    health_failures: List[str] = []
    business_failures: List[str] = []
    for index, item in enumerate(evidence):
        raw = _raw(item)
        status = _field(item, ("status_code", "status", "http.status_code", "http_status"))
        endpoint = _field(item, ("endpoint", "route", "path", "http.route", "url", "request_path"))
        if status is None:
            match = re.search(r"\b([1-5]\d\d)\b", str(item.get("message") or raw.get("message") or ""))
            status = match.group(1) if match else None
        family = _status_family(status)
        if not family and endpoint is None:
            continue
        evidence_id = _evidence_id(item, index)
        if family:
            families[family] += 1
        if endpoint:
            key = str(endpoint)[:180]
            endpoints[key]["count"] += 1
            if family:
                endpoints[key]["families"][family] += 1
            if evidence_id not in endpoints[key]["evidence_ids"]:
                endpoints[key]["evidence_ids"].append(evidence_id)
            endpoint_lower = key.lower()
            is_failure = family in {"4xx", "5xx"} or any(token in _text(item) for token in ("timeout", "failed", "unavailable", "error"))
            if is_failure:
                if any(token in endpoint_lower for token in ("/health", "/ready", "/readiness", "/live", "/liveness")):
                    health_failures.append(evidence_id)
                else:
                    business_failures.append(evidence_id)
    endpoint_rows = [
        {
            "endpoint": endpoint,
            "count": row["count"],
            "status_families": dict(row["families"]),
            "evidence_ids": row["evidence_ids"][:8],
        }
        for endpoint, row in endpoints.items()
    ]
    endpoint_rows.sort(key=lambda row: (row["status_families"].get("5xx", 0), row["count"]), reverse=True)
    return {
        "status_families": dict(families),
        "endpoint_impacts": endpoint_rows[:16],
        "health_endpoint_failure_evidence_ids": health_failures[:12],
        "business_endpoint_failure_evidence_ids": business_failures[:12],
        "health_vs_business": (
            "health_and_business_impacted" if health_failures and business_failures
            else "health_only" if health_failures
            else "business_only" if business_failures
            else "not_established"
        ),
    }


def _normalize_signature(text: str) -> str:
    value = text.lower()
    value = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", value)
    value = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", value)
    value = re.sub(r"\b\d{2,}\b", "<n>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:280]


def _exception_type(text: str) -> Optional[str]:
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_.]*(?:Exception|Error|Timeout|Failure))\b", text)
    return match.group(1) if match else None


def _error_clusters(evidence: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    clusters: Dict[str, Dict[str, Any]] = {}
    for index, item in enumerate(evidence):
        if str(item.get("type") or "").lower() not in {"log", "event", "alert", "trace"}:
            continue
        raw = _raw(item)
        message = str(item.get("message") or raw.get("message") or raw.get("exception") or raw.get("error") or "")
        stack = str(raw.get("stacktrace") or raw.get("stack_trace") or raw.get("stack") or "")
        combined = " ".join((message, stack)).strip()
        if not combined or not any(token in combined.lower() for token in ("error", "exception", "timeout", "failed", "failure", "5xx", "500", "reset", "refused")):
            continue
        signature_text = _normalize_signature(message or stack)
        digest = hashlib.sha1(signature_text.encode("utf-8"), usedforsecurity=False).hexdigest()[:14]
        stamp = _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at"))
        evidence_id = _evidence_id(item, index)
        cluster = clusters.setdefault(digest, {
            "signature": signature_text,
            "count": 0,
            "exception_type": _exception_type(combined),
            "first_seen": None,
            "last_seen": None,
            "evidence_ids": [],
            "stack_pattern": _normalize_signature(stack)[:220] if stack else None,
        })
        cluster["count"] += 1
        if evidence_id not in cluster["evidence_ids"]:
            cluster["evidence_ids"].append(evidence_id)
        if stamp:
            current_first = _parse_timestamp(cluster["first_seen"])
            current_last = _parse_timestamp(cluster["last_seen"])
            if current_first is None or stamp < current_first:
                cluster["first_seen"] = stamp.isoformat()
            if current_last is None or stamp > current_last:
                cluster["last_seen"] = stamp.isoformat()
    rows = list(clusters.values())
    rows.sort(key=lambda row: row["count"], reverse=True)
    return rows[:16]


def _keyword_evidence(evidence: List[Mapping[str, Any]], groups: Mapping[str, Sequence[str]]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {name: [] for name in groups}
    for index, item in enumerate(evidence):
        text = _text(item)
        evidence_id = _evidence_id(item, index)
        for name, tokens in groups.items():
            if any(token in text for token in tokens) and evidence_id not in result[name]:
                result[name].append(evidence_id)
    return {name: ids[:16] for name, ids in result.items()}


def _trace_features(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    spans: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        raw = _raw(item)
        text = _text(item)
        has_trace = str(item.get("type") or "").lower() == "trace" or any(key in raw for key in ("trace_id", "span_id", "parent_span_id")) or " span " in f" {text} "
        if not has_trace:
            continue
        duration = _numeric(_first(raw, ("duration_ms", "latency_ms", "duration", "latency")))
        if duration is None:
            duration = _numeric(item.get("value"))
        status = str(_first(raw, ("status", "status_code", "span_status")) or "").lower()
        error = bool(raw.get("error")) or status in {"error", "failed", "failure"} or any(token in text for token in ("exception", "timeout", "reset", "error"))
        caller = _first(raw, ("caller", "source_service", "upstream", "service"))
        callee = _first(raw, ("callee", "destination_service", "downstream", "peer_service"))
        spans.append({
            "evidence_id": _evidence_id(item, index),
            "trace_id": raw.get("trace_id"),
            "span_id": raw.get("span_id"),
            "parent_span_id": raw.get("parent_span_id"),
            "name": raw.get("span_name") or item.get("name"),
            "caller": caller,
            "callee": callee,
            "duration_ms": duration,
            "error": error,
            "status": status or None,
        })
    duration_values = [span["duration_ms"] for span in spans if span.get("duration_ms") is not None]
    slow_threshold = None
    if duration_values:
        ordered = sorted(float(value) for value in duration_values)
        slow_threshold = ordered[max(0, int(len(ordered) * 0.9) - 1)]
    slow = [span for span in spans if span.get("duration_ms") is not None and slow_threshold is not None and float(span["duration_ms"]) >= slow_threshold]
    slow.sort(key=lambda row: float(row.get("duration_ms") or 0), reverse=True)
    errors = [span for span in spans if span.get("error")]
    critical_path = sorted(
        [span for span in spans if span.get("duration_ms") is not None],
        key=lambda row: float(row.get("duration_ms") or 0),
        reverse=True,
    )[:8]
    downstream = Counter(str(span.get("callee")) for span in errors + slow if span.get("callee"))
    return {
        "trace_evidence_count": len(spans),
        "slow_spans": slow[:12],
        "error_spans": errors[:12],
        "critical_path_candidates": critical_path,
        "downstream_contributors": [{"service": name, "signal_count": count} for name, count in downstream.most_common(8)],
    }


def _dependency_features(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    handoffs: Dict[str, Dict[str, Any]] = {}
    for index, item in enumerate(evidence):
        raw = _raw(item)
        text = _text(item)
        dependency = _first(raw, ("callee", "destination_service", "downstream", "dependency", "peer_service", "database"))
        if dependency is None and not any(token in text for token in ("downstream", "upstream", "dependency", "database", "postgres", "mysql", "redis", "dns", "packet loss", "connection reset")):
            continue
        evidence_id = _evidence_id(item, index)
        latency = _numeric(_first(raw, ("latency_ms", "duration_ms", "latency", "duration")))
        error_rate = _numeric(_first(raw, ("error_rate", "failure_rate")))
        row = {
            "evidence_id": evidence_id,
            "dependency": str(dependency) if dependency is not None else None,
            "latency_ms": latency,
            "error_rate": error_rate,
            "timeout": "timeout" in text,
            "reset": "reset" in text,
            "retry": "retry" in text,
            "signal": text[:220],
        }
        rows.append(row)
        targets: List[Tuple[str, str]] = []
        if any(token in text for token in ("postgres", "mysql", "database", "sql", "db timeout", "connection pool")):
            targets.append(("database", "database/downstream evidence is stronger than an application-only explanation"))
        if any(token in text for token in ("dns", "packet loss", "connection reset", "network unreachable", "route")):
            targets.append(("network", "network-path evidence is stronger than an application-only explanation"))
        if dependency is not None or any(token in text for token in ("downstream", "upstream", "dependency")):
            targets.append(("dependency", "downstream dependency contribution is evidenced"))
        for target, reason in targets:
            handoffs.setdefault(target, {"agent": target, "reason": reason, "evidence_ids": []})["evidence_ids"].append(evidence_id)
    return {"signals": rows[:20], "handoff_candidates": list(handoffs.values())[:6]}


def _change_features(evidence: List[Mapping[str, Any]], first_anomaly: Optional[datetime]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        text = _text(item)
        if str(item.get("type") or "").lower() not in {"change", "event", "log"} and not any(token in text for token in ("deploy", "release", "rollout", "feature flag", "config", "version", "image digest")):
            continue
        if not any(token in text for token in ("deploy", "release", "rollout", "feature flag", "config", "version", "image digest")):
            continue
        raw = _raw(item)
        stamp = _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at") or raw.get("timestamp"))
        delta_seconds = None
        if stamp and first_anomaly:
            delta_seconds = round((first_anomaly - stamp).total_seconds(), 3)
        rows.append({
            "evidence_id": _evidence_id(item, index),
            "timestamp": stamp.isoformat() if stamp else None,
            "seconds_before_first_anomaly": delta_seconds,
            "release": _first(raw, ("release", "version", "image", "image_digest")),
            "config_version": _first(raw, ("config_version", "config_hash", "configuration_version")),
            "feature_flag": _first(raw, ("feature_flag", "flag", "flag_name")),
            "scope": _first(raw, ("service", "component", "environment", "region", "instance")),
        })
    temporally_close = [row for row in rows if row.get("seconds_before_first_anomaly") is not None and 0 <= float(row["seconds_before_first_anomaly"]) <= 1800]
    return {
        "candidate_changes": rows[:16],
        "temporally_close_changes": temporally_close[:10],
        "policy": "temporal proximity is correlation only; require before/after deltas or affected-scope overlap before raising causal confidence",
    }


def _scope_features(evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    regions: Dict[str, Counter[str]] = defaultdict(Counter)
    instances: Dict[str, Counter[str]] = defaultdict(Counter)
    for item in evidence:
        region = _field(item, ("region", "zone", "availability_zone"))
        instance = _field(item, ("instance", "host", "hostname", "pod"))
        text = _text(item)
        unhealthy = any(token in text for token in ("error", "failed", "failure", "timeout", "5xx", "degraded", "unhealthy", "saturated", "exhaust"))
        healthy = any(token in text for token in ("healthy", "success", "normal", "ok", "available")) and not unhealthy
        state = "unhealthy" if unhealthy else "healthy" if healthy else "unknown"
        if region:
            regions[str(region)][state] += 1
        if instance:
            instances[str(instance)][state] += 1
    unhealthy_instances = [name for name, counts in instances.items() if counts["unhealthy"] > counts["healthy"]]
    healthy_instances = [name for name, counts in instances.items() if counts["healthy"] > counts["unhealthy"]]
    if unhealthy_instances and healthy_instances:
        outage_scope = "partial_instance_outage"
    elif unhealthy_instances and not healthy_instances and len(unhealthy_instances) >= 2:
        outage_scope = "multi_instance_outage_observed"
    else:
        outage_scope = "not_established"
    return {
        "regions": {name: dict(counts) for name, counts in list(regions.items())[:12]},
        "instances": {name: dict(counts) for name, counts in list(instances.items())[:20]},
        "outage_scope": outage_scope,
        "affected_instances": unhealthy_instances[:16],
        "healthy_comparison_instances": healthy_instances[:16],
    }


def _conflicts(evidence: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    healthy: List[str] = []
    unhealthy: List[str] = []
    for index, item in enumerate(evidence):
        text = _text(item)
        evidence_id = _evidence_id(item, index)
        bad = any(token in text for token in ("error", "failed", "failure", "timeout", "5xx", "degraded", "unhealthy", "saturated", "exhausted"))
        good = any(token in text for token in ("healthy", "normal", "success", "ok", "available"))
        if bad:
            unhealthy.append(evidence_id)
        if good and not bad:
            healthy.append(evidence_id)
    if healthy and unhealthy:
        return [{
            "kind": "healthy_vs_unhealthy_application_evidence",
            "supporting_failure_evidence_ids": unhealthy[:10],
            "conflicting_healthy_evidence_ids": healthy[:10],
        }]
    return []


def _first_anomaly(evidence: List[Mapping[str, Any]]) -> Optional[datetime]:
    rows: List[datetime] = []
    for item in evidence:
        text = _text(item)
        if not any(token in text for token in ("error", "exception", "timeout", "5xx", "latency", "saturat", "exhaust", "failed", "failure")):
            continue
        stamp = _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at"))
        if stamp:
            rows.append(stamp)
    return min(rows) if rows else None


def _traffic_vs_regression(metric_features: Mapping[str, Any], change_features: Mapping[str, Any], resource_signals: Mapping[str, Sequence[str]]) -> Dict[str, Any]:
    request_rows = metric_features.get("red", {}).get("request_rate", []) if isinstance(metric_features.get("red"), Mapping) else []
    error_rows = metric_features.get("red", {}).get("error_rate", []) if isinstance(metric_features.get("red"), Mapping) else []
    latency_rows = metric_features.get("red", {}).get("duration_latency", []) if isinstance(metric_features.get("red"), Mapping) else []

    def max_relative(rows: Sequence[Mapping[str, Any]]) -> Optional[float]:
        values = [row.get("delta", {}).get("relative") for row in rows if isinstance(row.get("delta"), Mapping)]
        numeric = [float(value) for value in values if value is not None]
        return max(numeric) if numeric else None

    traffic_delta = max_relative(request_rows)
    error_delta = max_relative(error_rows)
    latency_delta = max_relative(latency_rows)
    saturation = bool(resource_signals.get("thread_pool") or resource_signals.get("connection_pool") or resource_signals.get("queue_backpressure") or resource_signals.get("cpu"))
    close_change = bool(change_features.get("temporally_close_changes"))

    classification = "insufficient_evidence"
    reasons: List[str] = []
    if traffic_delta is not None and traffic_delta >= 0.5 and saturation:
        classification = "traffic_driven_saturation_candidate"
        reasons.append("request rate increased materially while saturation/backpressure evidence is present")
    elif close_change and (error_delta is not None and error_delta > 0.2 or latency_delta is not None and latency_delta > 0.2) and (traffic_delta is None or traffic_delta < 0.3):
        classification = "software_or_config_regression_candidate"
        reasons.append("error/latency increased after a nearby change without a comparable traffic increase")
    elif traffic_delta is not None and traffic_delta >= 0.5 and not saturation and (error_delta is None or error_delta <= 0.1):
        classification = "traffic_spike_without_regression_evidence"
        reasons.append("traffic increased but error/saturation evidence does not establish a regression")
    return {
        "classification": classification,
        "request_rate_relative_delta": traffic_delta,
        "error_rate_relative_delta": error_delta,
        "latency_relative_delta": latency_delta,
        "saturation_signal_present": saturation,
        "temporally_close_change_present": close_change,
        "reasons": reasons,
    }


def build_application_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build bounded, explainable application reliability features before LLM synthesis.

    This engine deliberately does not declare root cause. It extracts RED, endpoint,
    log-signature, trace, dependency, release and saturation observations that the
    ApplicationAgent can synthesize with explicit falsification and handoff rules.
    """
    items = [item for item in evidence if isinstance(item, Mapping)]
    context = context or {}
    first_anomaly = _first_anomaly(items)
    metrics = _metric_features(items)
    http = _http_features(items)
    clusters = _error_clusters(items)
    traces = _trace_features(items)
    dependencies = _dependency_features(items)
    changes = _change_features(items, first_anomaly)
    scope = _scope_features(items)
    conflicts = _conflicts(items)
    resources = _keyword_evidence(items, {
        "timeouts": ("timeout", "timed out"),
        "resets": ("connection reset", "reset by peer", "tcp reset"),
        "retries": ("retry", "retries", "retrying"),
        "retry_amplification": ("retry storm", "retry amplification", "retry rate", "excessive retries"),
        "thread_pool": ("thread pool", "worker pool", "worker exhaustion", "all workers busy", "worker queue"),
        "connection_pool": ("connection pool", "pool exhausted", "pool timeout", "too many connections"),
        "memory_gc": ("memory pressure", "out of memory", "oom", "gc pause", "garbage collection", "heap"),
        "cpu": ("cpu saturation", "process cpu", "cpu thrott", "cpu exhausted"),
        "fd_socket": ("file descriptor", "too many open files", "socket exhaustion", "open fds"),
        "queue_backpressure": ("backpressure", "queue depth", "queue full", "backlog", "pending work"),
        "slo_error_budget": ("slo", "error budget", "burn rate"),
    })
    traffic_vs_regression = _traffic_vs_regression(metrics, changes, resources)

    present_types = Counter(str(item.get("type") or "unknown").lower() for item in items)
    gaps: List[Dict[str, Any]] = []
    if not present_types.get("metric"):
        gaps.append({"evidence": "metric", "reason": "RED rates, latency percentiles and baseline deltas need live metrics", "information_gain": 1.0})
    if not present_types.get("log"):
        gaps.append({"evidence": "log", "reason": "error signatures, exceptions and stack patterns need live logs", "information_gain": 0.95})
    if not traces.get("trace_evidence_count"):
        gaps.append({"evidence": "trace", "reason": "critical path and downstream contribution are not directly observed", "information_gain": 0.85})
    if not metrics.get("largest_baseline_deltas"):
        gaps.append({"evidence": "baseline_metric", "reason": "before/incident/historical-normal comparison is missing", "information_gain": 0.9})
    if not changes.get("candidate_changes"):
        gaps.append({"evidence": "change", "reason": "release/config/feature-flag correlation cannot be tested", "information_gain": 0.7})
    if dependencies.get("signals") and not traces.get("trace_evidence_count"):
        gaps.append({"evidence": "dependency_trace", "reason": "downstream symptoms exist but trace-level contribution is missing", "information_gain": 0.88})

    return {
        "policy": "observations_not_root_cause; correlation_requires_falsification; downstream_evidence_can_override_application_symptom_attribution",
        "service": service_name,
        "first_anomaly": first_anomaly.isoformat() if first_anomaly else None,
        "evidence_count": len(items),
        "evidence_type_counts": dict(present_types),
        "red_features": metrics.get("red", {}),
        "latency_percentiles": metrics.get("latency_percentiles", {}),
        "tail_latency_present": metrics.get("tail_latency_present", False),
        "baseline_deltas": metrics.get("largest_baseline_deltas", []),
        "http": http,
        "error_signature_clusters": clusters,
        "resource_pressure": metrics.get("resource_pressure", {}),
        "resource_keyword_signals": resources,
        "retry_metrics": metrics.get("retry_metrics", []),
        "slo_signals": metrics.get("slo_signals", []),
        "trace_analysis": traces,
        "dependency_analysis": dependencies,
        "change_analysis": changes,
        "scope_analysis": scope,
        "traffic_vs_regression": traffic_vs_regression,
        "conflicts": conflicts,
        "evidence_gaps": gaps[:10],
        "next_best_evidence": gaps[:6],
        "context_summary": {
            "incident_start": context.get("incident_start") or context.get("started_at"),
            "environment": context.get("environment"),
            "customer_impact": context.get("customer_impact") or context.get("customer_impacting"),
        },
    }
