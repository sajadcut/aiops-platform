from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


SENSITIVE_TOKENS = (
    "authorization", "password", "passwd", "secret", "private_key", "privatekey",
    "access_token", "refresh_token", "id_token", "client_secret", "api_key", "apikey",
    "credential", "cookie", "set-cookie",
)

TRACE_TYPES = {"trace", "span", "apm_trace", "distributed_trace"}
TOPOLOGY_TYPES = {"topology", "service_map", "service-map", "dependency", "dependency_map"}
ANOMALY_WINDOW_SECONDS = 15 * 60
SHARED_DEPENDENCY_WINDOW_SECONDS = 10 * 60


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _labels(item: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = _raw(item)
    value = raw.get("labels") or raw.get("attributes") or raw.get("resource") or item.get("labels") or {}
    return value if isinstance(value, Mapping) else {}


def _evidence_id(item: Mapping[str, Any], index: int = 0) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


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


def _timestamp(item: Mapping[str, Any]) -> Optional[datetime]:
    return _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at") or _raw(item).get("timestamp"))


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


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
        elif re.fullmatch(r"[-+]?\d+(?:\.\d+)?s", candidate):
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
        result: List[str] = []
        for key, current in list(value.items())[:50]:
            normalized = str(key).lower().replace("-", "_")
            if any(token in normalized for token in SENSITIVE_TOKENS):
                continue
            result.extend(_flatten_text(current, depth + 1))
        return result
    if isinstance(value, (list, tuple)):
        result: List[str] = []
        for current in list(value)[:16]:
            result.extend(_flatten_text(current, depth + 1))
        return result
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    return []


def _text(item: Mapping[str, Any]) -> str:
    return " ".join(_flatten_text(item)).lower()


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


def _normalize_service(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text[:180] if text else None


def _virtual_node(prefix: str, evidence_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.:-]+", "-", evidence_id)[:90] or "unknown"
    return f"unknown::{prefix}::{safe}"


def _rate_fraction(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    if 1.0 < value <= 100.0:
        return value / 100.0
    return value


def _metric_name(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    return str(item.get("name") or item.get("metric") or raw.get("name") or raw.get("metric") or raw.get("item_key") or "").lower()


def _metric_kind(name: str) -> Optional[str]:
    value = name.lower()
    if any(token in value for token in ("request_rate", "requests_per_second", "requests_total", "rps", "qps", "throughput")):
        return "request_rate"
    if any(token in value for token in ("error_rate", "failure_rate", "errors_per_second", "5xx_rate", "http_5xx")):
        return "error_rate"
    if any(token in value for token in ("latency", "duration", "response_time", "request_time")):
        return "latency"
    if any(token in value for token in ("timeout", "timed_out")):
        return "timeout"
    if any(token in value for token in ("retry", "retries")):
        return "retry"
    if any(token in value for token in ("circuit_breaker", "circuitbreaker", "circuit_open")):
        return "circuit_breaker"
    return None


def _metric_value(item: Mapping[str, Any]) -> Optional[float]:
    raw = _raw(item)
    return _numeric(item.get("value") if item.get("value") is not None else _first(raw, ("value", "current", "latest")))


def _baseline(item: Mapping[str, Any]) -> Optional[float]:
    raw = _raw(item)
    for key in ("baseline", "baseline_value", "previous", "previous_value", "pre_incident", "pre_incident_value", "normal", "normal_value"):
        value = _numeric(raw.get(key))
        if value is not None:
            return value
    return None


def _status_code(item: Mapping[str, Any]) -> Optional[int]:
    value = _field(item, ("status_code", "http.status_code", "http_status", "response_status"))
    try:
        code = int(str(value).split(".", 1)[0])
        return code if 100 <= code <= 599 else None
    except (TypeError, ValueError):
        return None


def _node_kind(name: str, hints: Iterable[str] = ()) -> str:
    text = " ".join([name, *[str(value) for value in hints if value not in (None, "")]]).lower()
    if name.startswith("unknown::"):
        return "unknown"
    if any(token in text for token in ("postgres", "postgresql", "mysql", "mariadb", "oracle", "sqlserver", "mongodb", "mongo", "cassandra", "database", " db ")):
        return "database"
    if any(token in text for token in ("kafka", "rabbitmq", "rabbit", "nats", "pulsar", "activemq", "sqs", "sns", "pubsub", "message broker", " queue", "topic")):
        return "messaging"
    if any(token in text for token in ("identity", "auth", "oauth", "oidc", "sso", "keycloak", "okta", "cognito", "auth0", "ldap")):
        return "identity"
    if any(token in text for token in ("external", "saas", "third_party", "third-party", "stripe", "twilio", "salesforce", "github.com", "api.")):
        return "external_api"
    return "service"


def _dependency_semantic(item: Mapping[str, Any]) -> bool:
    kind = str(item.get("type") or "").lower()
    if kind in TRACE_TYPES | TOPOLOGY_TYPES:
        return True
    raw = _raw(item)
    explicit = (
        "caller", "callee", "source_service", "target_service", "upstream_service", "downstream_service",
        "peer_service", "peer.service", "dependency", "dependency_name", "remote_service", "destination_service",
    )
    if any(key in item or key in raw or key in _labels(item) for key in explicit):
        return True
    text = _text(item)
    return any(token in text for token in ("dependency timeout", "upstream timeout", "downstream timeout", "dependency unavailable", "service map", "circuit breaker"))


def _service_name(item: Mapping[str, Any]) -> Optional[str]:
    return _normalize_service(_field(item, ("service", "service_name", "service.name", "current_service", "app", "application")))


def _peer_name(item: Mapping[str, Any]) -> Optional[str]:
    return _normalize_service(_field(item, ("peer_service", "peer.service", "remote_service", "destination_service", "dependency", "dependency_name")))


def _direct_endpoints(item: Mapping[str, Any], evidence_id: str) -> Tuple[Optional[str], Optional[str], bool]:
    caller = _normalize_service(_field(item, ("caller", "source_service", "client_service", "upstream_service", "from_service", "from")))
    callee = _normalize_service(_field(item, ("callee", "target_service", "server_service", "downstream_service", "to_service", "to")))
    current = _service_name(item)
    peer = _peer_name(item)
    item_type = str(item.get("type") or "").lower()
    span_kind = str(_field(item, ("span_kind", "span.kind", "kind")) or "").lower()

    if item_type in TRACE_TYPES:
        if span_kind in {"server", "consumer"}:
            caller = caller or peer
            callee = callee or current
        else:
            caller = caller or current
            callee = callee or peer
    else:
        caller = caller or current
        callee = callee or peer

    semantic = _dependency_semantic(item)
    virtual = False
    if semantic and caller and not callee:
        callee = _virtual_node("callee", evidence_id)
        virtual = True
    elif semantic and callee and not caller:
        caller = _virtual_node("caller", evidence_id)
        virtual = True
    return caller, callee, virtual


def _nested_topology_items(item: Mapping[str, Any], index: int) -> List[Dict[str, Any]]:
    raw = _raw(item)
    edges = raw.get("edges") or item.get("edges")
    if not isinstance(edges, list):
        return []
    result: List[Dict[str, Any]] = []
    parent_id = _evidence_id(item, index)
    for edge_index, edge in enumerate(edges[:40]):
        if not isinstance(edge, Mapping):
            continue
        result.append({
            "id": f"{parent_id}:edge:{edge_index}",
            "type": "service_map",
            "source": item.get("source"),
            "timestamp": item.get("timestamp") or item.get("observed_at") or item.get("created_at"),
            "raw_data": dict(edge),
        })
    return result


def _observation(item: Mapping[str, Any], index: int, caller: str, callee: str, *, derived: bool = False) -> Dict[str, Any]:
    evidence_id = _evidence_id(item, index)
    timestamp = _timestamp(item)
    text = _text(item)
    raw = _raw(item)
    metric_name = _metric_name(item)
    metric_kind = _metric_kind(metric_name) if str(item.get("type") or "").lower() == "metric" else None
    metric_value = _metric_value(item) if metric_kind else None
    baseline = _baseline(item) if metric_kind else None
    duration = _numeric(_field(item, ("duration_ms", "latency_ms", "elapsed_ms", "duration", "latency")))
    status = str(_field(item, ("status", "span_status", "health", "state")) or "").lower()
    error_flag = bool(_field(item, ("error", "failed", "is_error"))) or status in {"error", "failed", "failure", "unhealthy", "down", "degraded"}
    code = _status_code(item)
    if code is not None and code >= 500:
        error_flag = True
    timeout_flag = bool(_field(item, ("timeout", "timed_out", "is_timeout"))) or any(token in text for token in ("timeout", "timed out", "deadline exceeded"))
    retry_value = _numeric(_field(item, ("retry", "retries", "retry_count", "retry_rate")))
    request_rate = _numeric(_field(item, ("request_rate", "rps", "qps", "throughput")))
    error_rate = _numeric(_field(item, ("error_rate", "failure_rate", "5xx_rate")))
    latency = duration
    timeout_value = _numeric(_field(item, ("timeout_rate", "timeouts", "timeout_count")))
    circuit_open = bool(_field(item, ("circuit_open", "circuit_breaker_open"))) or any(
        token in text for token in ("circuit breaker open", "circuit open", "circuit-breaker open", "breaker tripped")
    )

    if metric_kind == "request_rate":
        request_rate = metric_value
    elif metric_kind == "error_rate":
        error_rate = metric_value
    elif metric_kind == "latency":
        latency = metric_value
    elif metric_kind == "timeout":
        timeout_value = metric_value
    elif metric_kind == "retry":
        retry_value = metric_value
    elif metric_kind == "circuit_breaker" and metric_value is not None:
        circuit_open = metric_value > 0

    anomaly_reasons: List[str] = []
    if error_flag:
        anomaly_reasons.append("error_observed")
    if timeout_flag:
        anomaly_reasons.append("timeout_observed")
    if circuit_open:
        anomaly_reasons.append("circuit_breaker_open")
    if status in {"unhealthy", "down", "degraded", "failed", "failure", "error"}:
        anomaly_reasons.append("dependency_health_degraded")

    if metric_kind == "error_rate" and metric_value is not None:
        current = _rate_fraction(metric_value)
        previous = _rate_fraction(baseline)
        if previous is not None:
            if current is not None and current - previous >= max(0.01, abs(previous) * 0.5):
                anomaly_reasons.append("error_rate_regression")
        elif current is not None and current >= 0.05:
            anomaly_reasons.append("elevated_error_rate")
    elif metric_kind == "latency" and metric_value is not None:
        if baseline is not None and baseline >= 0 and metric_value > max(baseline * 1.5, baseline + 25.0):
            anomaly_reasons.append("latency_regression")
        elif any(token in text for token in ("high latency", "latency spike", "slow dependency")):
            anomaly_reasons.append("latency_anomaly")
    elif metric_kind == "timeout" and metric_value is not None and metric_value > 0:
        anomaly_reasons.append("timeout_metric_nonzero")
    elif metric_kind == "retry" and metric_value is not None:
        if baseline is not None and metric_value > max(baseline * 2.0, baseline + 1.0):
            anomaly_reasons.append("retry_regression")
        elif any(token in text for token in ("retry storm", "retry amplification", "excessive retries")):
            anomaly_reasons.append("retry_amplification")

    if any(token in text for token in ("connection refused", "connection reset", "unavailable", "upstream failure", "dependency outage", "service unavailable")):
        anomaly_reasons.append("dependency_failure_signal")

    dependency_type_hint = _field(item, ("dependency_type", "component_type", "peer_type", "kind"))
    region = _field(item, ("region", "zone", "availability_zone", "aws.region", "cloud.region"))
    version = _field(item, ("dependency_version", "peer_version", "version", "release"))
    previous_version = _field(item, ("previous_version", "from_version", "old_version"))
    change = _field(item, ("change", "change_type", "deployment", "release_change"))

    return {
        "evidence_id": evidence_id,
        "timestamp": timestamp,
        "caller": caller,
        "callee": callee,
        "source_type": str(item.get("type") or "unknown").lower(),
        "source": str(item.get("source") or "unknown"),
        "derived_from_parent_child": derived,
        "metric_kind": metric_kind,
        "metric_value": metric_value,
        "baseline": baseline,
        "request_rate": request_rate,
        "error_rate": error_rate,
        "latency": latency,
        "timeout": timeout_value,
        "retry": retry_value,
        "error_flag": error_flag,
        "timeout_flag": timeout_flag,
        "circuit_open": circuit_open,
        "anomaly_reasons": _unique(anomaly_reasons, 12),
        "dependency_type_hint": dependency_type_hint,
        "region": region,
        "version": version,
        "previous_version": previous_version,
        "change": change,
        "trace_id": _field(item, ("trace_id", "trace.id")),
        "span_id": _field(item, ("span_id", "span.id")),
        "parent_span_id": _field(item, ("parent_span_id", "parent.span.id")),
    }


def _trace_parent_child_observations(evidence: List[Mapping[str, Any]], start_index: int) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    spans_by_trace: Dict[str, Dict[str, Tuple[Mapping[str, Any], str]]] = defaultdict(dict)
    trace_span_count = 0
    parent_refs = 0
    missing_parent_refs = 0
    resolved_parent_refs = 0

    for index, item in enumerate(evidence):
        item_type = str(item.get("type") or "").lower()
        trace_id = _field(item, ("trace_id", "trace.id"))
        span_id = _field(item, ("span_id", "span.id"))
        if item_type not in TRACE_TYPES and not (trace_id and span_id):
            continue
        if not trace_id or not span_id:
            continue
        trace_span_count += 1
        spans_by_trace[str(trace_id)][str(span_id)] = (item, _evidence_id(item, index))

    result: List[Dict[str, Any]] = []
    sequence = start_index
    for trace_id, spans in spans_by_trace.items():
        for span_id, (item, evidence_id) in spans.items():
            parent_id = _field(item, ("parent_span_id", "parent.span.id"))
            if not parent_id:
                continue
            parent_refs += 1
            current_service = _service_name(item)
            parent = spans.get(str(parent_id))
            if parent is None:
                missing_parent_refs += 1
                if current_service:
                    synthetic = {
                        "id": f"{evidence_id}:missing-parent",
                        "type": "trace",
                        "source": item.get("source"),
                        "timestamp": item.get("timestamp") or item.get("observed_at") or item.get("created_at"),
                        "raw_data": {
                            "caller": _virtual_node(f"trace-parent:{trace_id}", str(parent_id)),
                            "callee": current_service,
                            "trace_id": trace_id,
                            "span_id": span_id,
                            "parent_span_id": parent_id,
                            "error": _field(item, ("error", "failed", "is_error")),
                            "status": _field(item, ("status", "span_status")),
                            "duration_ms": _field(item, ("duration_ms", "latency_ms", "duration")),
                        },
                    }
                    caller, callee, _ = _direct_endpoints(synthetic, synthetic["id"])
                    if caller and callee:
                        result.append(_observation(synthetic, sequence, caller, callee, derived=True))
                        sequence += 1
                continue
            resolved_parent_refs += 1
            parent_item, parent_evidence_id = parent
            parent_service = _service_name(parent_item)
            if parent_service and current_service and parent_service != current_service:
                synthetic = {
                    "id": f"{parent_evidence_id}->{evidence_id}",
                    "type": "trace",
                    "source": item.get("source") or parent_item.get("source"),
                    "timestamp": item.get("timestamp") or item.get("observed_at") or item.get("created_at"),
                    "raw_data": {
                        "caller": parent_service,
                        "callee": current_service,
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "parent_span_id": parent_id,
                        "error": _field(item, ("error", "failed", "is_error")),
                        "status": _field(item, ("status", "span_status")),
                        "duration_ms": _field(item, ("duration_ms", "latency_ms", "duration")),
                    },
                }
                result.append(_observation(synthetic, sequence, parent_service, current_service, derived=True))
                sequence += 1

    return result, {
        "trace_span_count": trace_span_count,
        "parent_reference_count": parent_refs,
        "resolved_parent_reference_count": resolved_parent_refs,
        "missing_parent_reference_count": missing_parent_refs,
    }


def _collect_edge_observations(evidence: List[Mapping[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    expanded: List[Mapping[str, Any]] = []
    for index, item in enumerate(evidence):
        expanded.append(item)
        expanded.extend(_nested_topology_items(item, index))

    observations: List[Dict[str, Any]] = []
    trace_endpoint_count = 0
    trace_resolved_endpoint_count = 0
    for index, item in enumerate(expanded):
        if not _dependency_semantic(item):
            continue
        evidence_id = _evidence_id(item, index)
        caller, callee, _ = _direct_endpoints(item, evidence_id)
        if not caller or not callee or caller == callee:
            continue
        observation = _observation(item, index, caller, callee)
        observations.append(observation)
        if observation["source_type"] in TRACE_TYPES:
            trace_endpoint_count += 1
            if not caller.startswith("unknown::") and not callee.startswith("unknown::"):
                trace_resolved_endpoint_count += 1

    derived, trace_stats = _trace_parent_child_observations(evidence, len(expanded) + 1)
    observations.extend(derived)
    trace_stats["trace_endpoint_observation_count"] = trace_endpoint_count + len(derived)
    trace_stats["trace_resolved_endpoint_observation_count"] = trace_resolved_endpoint_count + sum(
        1 for row in derived if not row["caller"].startswith("unknown::") and not row["callee"].startswith("unknown::")
    )
    return observations, trace_stats


def _latest_numeric(rows: List[Dict[str, Any]], field: str, *, normalize_rate: bool = False) -> Optional[float]:
    candidates = [row for row in rows if row.get(field) is not None]
    if not candidates:
        return None
    candidates.sort(key=lambda row: row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc))
    value = _numeric(candidates[-1].get(field))
    if normalize_rate:
        value = _rate_fraction(value)
    return None if value is None else round(value, 6)


def _metric_summary(rows: List[Dict[str, Any]], field: str, *, normalize_rate: bool = False) -> Dict[str, Optional[float]]:
    values: List[float] = []
    for row in rows:
        value = _numeric(row.get(field))
        if value is not None:
            values.append(_rate_fraction(value) if normalize_rate else value)
    values = [value for value in values if value is not None]
    if not values:
        return {"latest": None, "min": None, "max": None}
    return {
        "latest": _latest_numeric(rows, field, normalize_rate=normalize_rate),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
    }


def _aggregate_edges(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in observations:
        grouped[(row["caller"], row["callee"])].append(row)

    edges: List[Dict[str, Any]] = []
    for (caller, callee), rows in grouped.items():
        timestamps = sorted([row["timestamp"] for row in rows if row.get("timestamp") is not None])
        anomaly_rows = [row for row in rows if row.get("anomaly_reasons")]
        anomaly_times = sorted([row["timestamp"] for row in anomaly_rows if row.get("timestamp") is not None])
        trace_rows = [row for row in rows if row.get("source_type") in TRACE_TYPES]
        trace_error_count = sum(1 for row in trace_rows if row.get("error_flag"))
        trace_timeout_count = sum(1 for row in trace_rows if row.get("timeout_flag"))
        request_rate = _latest_numeric(rows, "request_rate")
        error_rate = _latest_numeric(rows, "error_rate", normalize_rate=True)
        latency = _latest_numeric(rows, "latency")
        timeout = _latest_numeric(rows, "timeout", normalize_rate=True)
        retry = _latest_numeric(rows, "retry")
        if error_rate is None and trace_rows:
            error_rate = round(trace_error_count / len(trace_rows), 6)
        if timeout is None and trace_rows:
            timeout = round(trace_timeout_count / len(trace_rows), 6)
        anomaly_reasons = _unique(
            reason for row in rows for reason in row.get("anomaly_reasons", []),
            20,
        )
        hints = _unique(row.get("dependency_type_hint") for row in rows, 8)
        regions = _unique(row.get("region") for row in rows, 12)
        versions = _unique(row.get("version") for row in rows, 12)
        changes = []
        for row in rows:
            if row.get("previous_version") or row.get("change"):
                changes.append({
                    "evidence_id": row["evidence_id"],
                    "timestamp": _iso(row.get("timestamp")),
                    "previous_version": row.get("previous_version"),
                    "version": row.get("version"),
                    "change": row.get("change"),
                })
        edges.append({
            "edge_id": f"{caller}->{callee}",
            "caller": caller,
            "callee": callee,
            "request_rate": request_rate,
            "error_rate": error_rate,
            "latency": latency,
            "timeout": timeout,
            "retry": retry,
            "time_window": {
                "start": _iso(timestamps[0]) if timestamps else None,
                "end": _iso(timestamps[-1]) if timestamps else None,
            },
            "anomaly_start": _iso(anomaly_times[0]) if anomaly_times else None,
            "anomaly_reasons": anomaly_reasons,
            "circuit_breaker": "open" if any(row.get("circuit_open") for row in rows) else "not_observed",
            "dependency_type": _node_kind(callee, hints),
            "regions": regions,
            "versions": versions,
            "dependency_version_changes": changes[:8],
            "evidence_ids": _unique((row["evidence_id"] for row in rows), 20),
            "anomaly_evidence_ids": _unique((row["evidence_id"] for row in anomaly_rows), 16),
            "trace_observation_count": len(trace_rows),
            "trace_error_count": trace_error_count,
            "trace_timeout_count": trace_timeout_count,
            "metric_summaries": {
                "request_rate": _metric_summary(rows, "request_rate"),
                "error_rate": _metric_summary(rows, "error_rate", normalize_rate=True),
                "latency": _metric_summary(rows, "latency"),
                "timeout": _metric_summary(rows, "timeout", normalize_rate=True),
                "retry": _metric_summary(rows, "retry"),
            },
        })
    edges.sort(key=lambda row: (row.get("anomaly_start") is not None, row.get("anomaly_start") or "9999", row["edge_id"]), reverse=False)
    return edges


def _node_health(evidence: List[Mapping[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    nodes: Dict[str, Dict[str, Any]] = {}

    def ensure(name: str) -> Dict[str, Any]:
        if name not in nodes:
            nodes[name] = {
                "name": name,
                "kind": _node_kind(name),
                "virtual": name.startswith("unknown::"),
                "regions": [],
                "versions": [],
                "evidence_ids": [],
                "anomaly_evidence_ids": [],
                "earliest_anomaly": None,
                "explicit_health": [],
            }
        return nodes[name]

    for edge in edges:
        caller = ensure(edge["caller"])
        callee = ensure(edge["callee"])
        callee["kind"] = edge.get("dependency_type") or callee["kind"]
        for node in (caller, callee):
            node["evidence_ids"] = _unique([*node["evidence_ids"], *edge.get("evidence_ids", [])], 24)
        callee["regions"] = _unique([*callee["regions"], *edge.get("regions", [])], 12)
        callee["versions"] = _unique([*callee["versions"], *edge.get("versions", [])], 12)
        if edge.get("anomaly_start"):
            callee["anomaly_evidence_ids"] = _unique([*callee["anomaly_evidence_ids"], *edge.get("anomaly_evidence_ids", [])], 20)
            if callee["earliest_anomaly"] is None or edge["anomaly_start"] < callee["earliest_anomaly"]:
                callee["earliest_anomaly"] = edge["anomaly_start"]

    for index, item in enumerate(evidence):
        service = _service_name(item)
        if not service:
            continue
        node = ensure(service)
        evidence_id = _evidence_id(item, index)
        node["evidence_ids"] = _unique([*node["evidence_ids"], evidence_id], 24)
        region = _field(item, ("region", "zone", "availability_zone", "cloud.region"))
        version = _field(item, ("version", "release", "service_version", "service.version"))
        node["regions"] = _unique([*node["regions"], region], 12)
        node["versions"] = _unique([*node["versions"], version], 12)
        status = str(_field(item, ("health", "health_status", "status", "state")) or "").lower()
        text = _text(item)
        unhealthy = status in {"unhealthy", "down", "degraded", "failed", "failure", "error"}
        if str(item.get("type") or "").lower() == "log" and any(token in text for token in ("error", "failed", "timeout", "unavailable", "exception")):
            unhealthy = True
        if unhealthy:
            timestamp = _timestamp(item)
            node["explicit_health"] = _unique([*node["explicit_health"], status or "error_signal"], 8)
            node["anomaly_evidence_ids"] = _unique([*node["anomaly_evidence_ids"], evidence_id], 20)
            iso = _iso(timestamp)
            if iso and (node["earliest_anomaly"] is None or iso < node["earliest_anomaly"]):
                node["earliest_anomaly"] = iso
        elif status in {"healthy", "ok", "up", "ready", "available"}:
            node["explicit_health"] = _unique([*node["explicit_health"], status], 8)

    result = []
    for node in nodes.values():
        explicit = set(node["explicit_health"])
        if explicit & {"unhealthy", "down", "degraded", "failed", "failure", "error", "error_signal"}:
            status = "degraded"
        elif node["anomaly_evidence_ids"]:
            status = "suspected_degraded"
        elif explicit & {"healthy", "ok", "up", "ready", "available"}:
            status = "healthy"
        else:
            status = "unknown"
        result.append({**node, "health_status": status})
    result.sort(key=lambda row: (row["virtual"], row["name"]))
    return result


def _fanout(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    outgoing: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        outgoing[edge["caller"]].append(edge)
    rows = []
    for caller, values in outgoing.items():
        rows.append({
            "service": caller,
            "dependency_count": len({edge["callee"] for edge in values}),
            "dependencies": _unique((edge["callee"] for edge in values), 20),
            "anomalous_dependency_count": sum(1 for edge in values if edge.get("anomaly_start")),
        })
    rows.sort(key=lambda row: (row["dependency_count"], row["anomalous_dependency_count"]), reverse=True)
    return rows[:20]


def _shared_dependencies(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    incoming: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if edge.get("anomaly_start"):
            incoming[edge["callee"]].append(edge)
    result = []
    for callee, values in incoming.items():
        callers = sorted({edge["caller"] for edge in values})
        if len(callers) < 2:
            continue
        times = [_parse_timestamp(edge.get("anomaly_start")) for edge in values]
        times = sorted([value for value in times if value is not None])
        clustered = bool(times and (times[-1] - times[0]).total_seconds() <= SHARED_DEPENDENCY_WINDOW_SECONDS)
        result.append({
            "dependency": callee,
            "dependency_type": values[0].get("dependency_type"),
            "affected_callers": callers,
            "affected_caller_count": len(callers),
            "earliest_anomaly": _iso(times[0]) if times else None,
            "latest_anomaly": _iso(times[-1]) if times else None,
            "clustered_in_time": clustered,
            "evidence_ids": _unique((eid for edge in values for eid in edge.get("anomaly_evidence_ids", [])), 20),
        })
    result.sort(key=lambda row: (row["clustered_in_time"], row["affected_caller_count"]), reverse=True)
    return result[:16]


def _retry_amplification(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    for edge in edges:
        retry = _numeric(edge.get("retry"))
        request_rate = _numeric(edge.get("request_rate"))
        ratio = None
        if retry is not None and request_rate not in (None, 0):
            ratio = retry / abs(request_rate)
        explicit = "retry_amplification" in edge.get("anomaly_reasons", [])
        amplified = explicit or (ratio is not None and ratio >= 0.20)
        if not amplified:
            continue
        result.append({
            "edge_id": edge["edge_id"],
            "caller": edge["caller"],
            "callee": edge["callee"],
            "retry": retry,
            "request_rate": request_rate,
            "retry_to_request_ratio": None if ratio is None else round(ratio, 4),
            "anomaly_start": edge.get("anomaly_start"),
            "evidence_ids": edge.get("evidence_ids", [])[:12],
        })
    result.sort(key=lambda row: float(row.get("retry_to_request_ratio") or 0.0), reverse=True)
    return result[:16]


def _circuit_breakers(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "edge_id": edge["edge_id"],
            "caller": edge["caller"],
            "callee": edge["callee"],
            "state": edge["circuit_breaker"],
            "anomaly_start": edge.get("anomaly_start"),
            "evidence_ids": edge.get("anomaly_evidence_ids", [])[:12],
        }
        for edge in edges if edge.get("circuit_breaker") == "open"
    ][:16]


def _timeout_propagation(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_callee: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if edge.get("anomaly_start") and ("timeout_observed" in edge.get("anomaly_reasons", []) or "timeout_metric_nonzero" in edge.get("anomaly_reasons", [])):
            by_callee[edge["callee"]].append(edge)

    result = []
    for root in edges:
        root_time = _parse_timestamp(root.get("anomaly_start"))
        if root_time is None or not ("timeout_observed" in root.get("anomaly_reasons", []) or "timeout_metric_nonzero" in root.get("anomaly_reasons", [])):
            continue
        upstream_edges = by_callee.get(root["caller"], [])
        for upstream in upstream_edges:
            upstream_time = _parse_timestamp(upstream.get("anomaly_start"))
            if upstream_time is None or upstream_time < root_time:
                continue
            delta = (upstream_time - root_time).total_seconds()
            if delta > ANOMALY_WINDOW_SECONDS:
                continue
            result.append({
                "downstream_edge": root["edge_id"],
                "upstream_edge": upstream["edge_id"],
                "propagation_seconds": round(delta, 3),
                "direction": "downstream_to_upstream",
                "evidence_ids": _unique([*root.get("anomaly_evidence_ids", []), *upstream.get("anomaly_evidence_ids", [])], 20),
            })
    result.sort(key=lambda row: row["propagation_seconds"])
    return result[:20]


def _cascade_chains(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    anomalous = [edge for edge in edges if edge.get("anomaly_start")]
    by_callee: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in anomalous:
        by_callee[edge["callee"]].append(edge)
    result = []
    for root in anomalous:
        root_time = _parse_timestamp(root.get("anomaly_start"))
        if root_time is None:
            continue
        chain = [root]
        seen = {root["edge_id"]}
        current = root
        while len(chain) < 8:
            candidates = []
            for upstream in by_callee.get(current["caller"], []):
                if upstream["edge_id"] in seen:
                    continue
                timestamp = _parse_timestamp(upstream.get("anomaly_start"))
                current_time = _parse_timestamp(current.get("anomaly_start"))
                if timestamp is None or current_time is None or timestamp < current_time:
                    continue
                if (timestamp - current_time).total_seconds() > ANOMALY_WINDOW_SECONDS:
                    continue
                candidates.append((timestamp, upstream))
            if not candidates:
                break
            candidates.sort(key=lambda row: row[0])
            current = candidates[0][1]
            seen.add(current["edge_id"])
            chain.append(current)
        if len(chain) < 2:
            continue
        result.append({
            "root_edge": chain[0]["edge_id"],
            "edge_sequence": [edge["edge_id"] for edge in chain],
            "service_sequence": [chain[0]["callee"], *[edge["caller"] for edge in chain]],
            "start": chain[0]["anomaly_start"],
            "end": chain[-1]["anomaly_start"],
            "evidence_ids": _unique((eid for edge in chain for eid in edge.get("anomaly_evidence_ids", [])), 24),
            "direction": "downstream_failure_propagating_to_upstream_callers",
        })
    result.sort(key=lambda row: len(row["edge_sequence"]), reverse=True)
    return result[:12]


def _critical_paths(edges: List[Dict[str, Any]], service_name: Optional[str]) -> List[Dict[str, Any]]:
    adjacency: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    indegree: Dict[str, int] = defaultdict(int)
    nodes: Set[str] = set()
    for edge in edges:
        adjacency[edge["caller"]].append(edge)
        indegree[edge["callee"]] += 1
        nodes.add(edge["caller"])
        nodes.add(edge["callee"])
    starts: List[str] = []
    if service_name and service_name in nodes:
        starts.append(service_name)
    starts.extend(sorted(node for node in nodes if indegree[node] == 0 and node not in starts))
    if not starts:
        starts = sorted(nodes)[:4]

    paths: List[Dict[str, Any]] = []

    def walk(node: str, path_edges: List[Dict[str, Any]], seen: Set[str]) -> None:
        if len(path_edges) >= 8 or not adjacency.get(node):
            if path_edges:
                _record(path_edges)
            return
        progressed = False
        for edge in adjacency[node][:12]:
            if edge["callee"] in seen:
                continue
            progressed = True
            walk(edge["callee"], [*path_edges, edge], {*seen, edge["callee"]})
        if not progressed and path_edges:
            _record(path_edges)

    def _record(path_edges: List[Dict[str, Any]]) -> None:
        latencies = [float(edge["latency"]) for edge in path_edges if edge.get("latency") is not None]
        anomalous = [edge for edge in path_edges if edge.get("anomaly_start")]
        nodes_path = [path_edges[0]["caller"], *[edge["callee"] for edge in path_edges]]
        score = min(1.0, 0.18 * len(anomalous) + 0.02 * len(path_edges) + min(sum(latencies) / 5000.0, 0.5))
        paths.append({
            "nodes": nodes_path,
            "edges": [edge["edge_id"] for edge in path_edges],
            "cumulative_latency": round(sum(latencies), 3) if latencies else None,
            "anomalous_edges": [edge["edge_id"] for edge in anomalous],
            "earliest_anomaly": min((edge["anomaly_start"] for edge in anomalous), default=None),
            "path_score": round(score, 4),
            "policy": "critical_path_candidate_not_root_cause",
        })

    for start in starts[:6]:
        walk(start, [], {start})
    unique_paths: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for path in paths:
        unique_paths[tuple(path["edges"])] = path
    result = list(unique_paths.values())
    result.sort(key=lambda row: (row["path_score"], row.get("cumulative_latency") or 0.0), reverse=True)
    return result[:12]


def _root_contributors(edges: List[Dict[str, Any]], nodes: List[Dict[str, Any]], shared: List[Dict[str, Any]], retries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    anomalous = [edge for edge in edges if edge.get("anomaly_start")]
    if not anomalous:
        return []
    anomalous.sort(key=lambda edge: edge["anomaly_start"])
    earliest_time = _parse_timestamp(anomalous[0]["anomaly_start"])
    node_map = {node["name"]: node for node in nodes}
    shared_map = {row["dependency"]: row for row in shared}
    retry_by_edge = {row["edge_id"]: row for row in retries}
    incoming_to: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    outgoing_from: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in anomalous:
        incoming_to[edge["callee"]].append(edge)
        outgoing_from[edge["caller"]].append(edge)

    result = []
    for index, edge in enumerate(anomalous):
        timestamp = _parse_timestamp(edge["anomaly_start"])
        if timestamp is None or earliest_time is None:
            continue
        delta = max(0.0, (timestamp - earliest_time).total_seconds())
        first_factor = 1.0 if delta <= 1.0 else 0.0
        earliest_factor = 1.0 / (1.0 + (delta / 300.0))
        callee_node = node_map.get(edge["callee"], {})
        downstream_health = str(callee_node.get("health_status") or "unknown")
        downstream_factor = 1.0 if downstream_health == "degraded" else 0.75 if downstream_health == "suspected_degraded" else 0.25 if downstream_health == "unknown" else 0.0
        retry_factor = 1.0 if edge["edge_id"] in retry_by_edge else 0.0
        for upstream in incoming_to.get(edge["caller"], []):
            upstream_time = _parse_timestamp(upstream.get("anomaly_start"))
            if upstream_time and upstream_time >= timestamp and upstream["edge_id"] in retry_by_edge:
                retry_factor = max(retry_factor, 1.0)
        shared_row = shared_map.get(edge["callee"])
        shared_factor = 1.0 if shared_row and shared_row.get("clustered_in_time") else 0.5 if shared_row else 0.0

        later_upstream = []
        for upstream in incoming_to.get(edge["caller"], []):
            upstream_time = _parse_timestamp(upstream.get("anomaly_start"))
            if upstream_time and upstream_time >= timestamp and (upstream_time - timestamp).total_seconds() <= ANOMALY_WINDOW_SECONDS:
                later_upstream.append(upstream)
        later_shared = []
        for peer in incoming_to.get(edge["callee"], []):
            if peer["edge_id"] == edge["edge_id"]:
                continue
            peer_time = _parse_timestamp(peer.get("anomaly_start"))
            if peer_time and peer_time >= timestamp and (peer_time - timestamp).total_seconds() <= SHARED_DEPENDENCY_WINDOW_SECONDS:
                later_shared.append(peer)
        deeper_earlier = []
        for deeper in outgoing_from.get(edge["callee"], []):
            deeper_time = _parse_timestamp(deeper.get("anomaly_start"))
            if deeper_time and deeper_time < timestamp:
                deeper_earlier.append(deeper)

        if later_upstream or later_shared:
            direction = "downstream_to_upstream_supported"
            propagation_factor = 1.0
        elif deeper_earlier:
            direction = "deeper_downstream_precedes_this_edge"
            propagation_factor = 0.0
        else:
            direction = "not_established"
            propagation_factor = 0.25

        strength = 0.0
        error_rate = _rate_fraction(_numeric(edge.get("error_rate")))
        timeout = _rate_fraction(_numeric(edge.get("timeout")))
        if error_rate is not None:
            strength = max(strength, min(1.0, error_rate / 0.25))
        if timeout is not None:
            strength = max(strength, min(1.0, timeout / 0.10))
        if edge.get("circuit_breaker") == "open":
            strength = max(strength, 0.9)
        if edge.get("anomaly_reasons"):
            strength = max(strength, 0.5)

        conflict_reasons: List[str] = []
        penalty = 0.0
        if deeper_earlier:
            conflict_reasons.append("deeper_downstream_edge_failed_earlier")
            penalty += 0.25
        if downstream_health == "healthy":
            conflict_reasons.append("callee_has_explicit_healthy_evidence")
            penalty += 0.20
        if edge["callee"].startswith("unknown::") or edge["caller"].startswith("unknown::"):
            conflict_reasons.append("virtual_or_uninstrumented_endpoint")
            penalty += 0.08

        score = (
            0.22 * first_factor
            + 0.13 * earliest_factor
            + 0.18 * downstream_factor
            + 0.12 * retry_factor
            + 0.15 * shared_factor
            + 0.15 * propagation_factor
            + 0.05 * strength
            - penalty
        )
        score = max(0.0, min(1.0, score))
        result.append({
            "edge_id": edge["edge_id"],
            "caller": edge["caller"],
            "callee": edge["callee"],
            "dependency_type": edge.get("dependency_type"),
            "root_contributor_score": round(score, 4),
            "root_cause_status": "causal_contributor_candidate_requires_falsification",
            "first_failing_edge": first_factor == 1.0,
            "earliest_anomaly": edge["anomaly_start"],
            "seconds_after_earliest_anomaly": round(delta, 3),
            "downstream_health": downstream_health,
            "upstream_retry_amplification": bool(retry_factor),
            "shared_node_effect": {
                "present": bool(shared_row),
                "affected_callers": list(shared_row.get("affected_callers", [])) if shared_row else [],
                "clustered_in_time": bool(shared_row.get("clustered_in_time")) if shared_row else False,
            },
            "error_propagation_direction": direction,
            "propagated_to_edges": _unique([*(row["edge_id"] for row in later_upstream), *(row["edge_id"] for row in later_shared)], 16),
            "deeper_downstream_predecessors": _unique((row["edge_id"] for row in deeper_earlier), 12),
            "score_factors": {
                "first_failing_edge": round(first_factor, 4),
                "earliest_anomaly": round(earliest_factor, 4),
                "downstream_health": round(downstream_factor, 4),
                "upstream_retry_amplification": round(retry_factor, 4),
                "shared_node_effect": round(shared_factor, 4),
                "error_propagation_direction": round(propagation_factor, 4),
                "anomaly_strength": round(strength, 4),
                "conflicting_evidence_penalty": round(penalty, 4),
            },
            "conflicting_evidence": conflict_reasons,
            "evidence_ids": edge.get("anomaly_evidence_ids", [])[:16],
            "falsification_checks": [
                f"Verify direct health of {edge['callee']} during the edge anomaly window",
                f"Compare {edge['caller']} behavior when {edge['callee']} is healthy versus degraded",
                "Check whether a deeper downstream edge failed earlier than this candidate",
            ],
        })
    result.sort(key=lambda row: (row["root_contributor_score"], -row["seconds_after_earliest_anomaly"]), reverse=True)
    return result[:20]


def _dependency_inventory(edges: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {
        "external_api": [],
        "database": [],
        "messaging": [],
        "identity": [],
        "regional": [],
        "version_or_change": [],
    }
    for edge in edges:
        row = {
            "edge_id": edge["edge_id"],
            "caller": edge["caller"],
            "callee": edge["callee"],
            "anomaly_start": edge.get("anomaly_start"),
            "evidence_ids": edge.get("evidence_ids", [])[:12],
        }
        kind = edge.get("dependency_type")
        if kind in {"external_api", "database", "messaging", "identity"}:
            result[kind].append(row)
        if edge.get("regions"):
            result["regional"].append({**row, "regions": edge["regions"]})
        if edge.get("versions") or edge.get("dependency_version_changes"):
            result["version_or_change"].append({
                **row,
                "versions": edge.get("versions", []),
                "changes": edge.get("dependency_version_changes", []),
            })
    return {key: values[:16] for key, values in result.items()}


def _trace_completeness(trace_stats: Mapping[str, int], observations: List[Dict[str, Any]], evidence: List[Mapping[str, Any]]) -> Dict[str, Any]:
    trace_span_count = int(trace_stats.get("trace_span_count", 0))
    endpoint_count = int(trace_stats.get("trace_endpoint_observation_count", 0))
    resolved_endpoint_count = int(trace_stats.get("trace_resolved_endpoint_observation_count", 0))
    parent_refs = int(trace_stats.get("parent_reference_count", 0))
    missing_parent = int(trace_stats.get("missing_parent_reference_count", 0))
    trace_evidence_present = trace_span_count > 0 or any(str(item.get("type") or "").lower() in TRACE_TYPES for item in evidence)
    topology_present = any(str(item.get("type") or "").lower() in TOPOLOGY_TYPES for item in evidence)

    endpoint_ratio = (resolved_endpoint_count / endpoint_count) if endpoint_count else (1.0 if trace_span_count and not parent_refs else 0.0)
    parent_ratio = ((parent_refs - missing_parent) / parent_refs) if parent_refs else (1.0 if trace_span_count else 0.0)
    if trace_evidence_present:
        completeness = max(0.0, min(1.0, 0.65 * endpoint_ratio + 0.35 * parent_ratio))
        mode = "trace_and_topology" if topology_present else "trace"
        uncertainty = "low" if completeness >= 0.80 else "medium" if completeness >= 0.45 else "high"
    else:
        completeness = 0.0
        mode = "topology_metrics_logs_fallback" if topology_present else "metrics_logs_fallback"
        uncertainty = "medium" if topology_present and observations else "high"

    ceiling = 0.90 if uncertainty == "low" else 0.72 if uncertainty == "medium" else 0.55
    return {
        "mode": mode,
        "trace_evidence_present": trace_evidence_present,
        "topology_evidence_present": topology_present,
        "trace_completeness": round(completeness, 4),
        "uncertainty_level": uncertainty,
        "confidence_ceiling": ceiling,
        **{key: int(value) for key, value in trace_stats.items()},
        "policy": "missing_trace_segments_or_unknown_nodes_increase_uncertainty; graph_absence_never_proves_dependency_absence",
    }


def build_dependency_causal_analysis(
    evidence: List[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a bounded directed service topology and rank causal dependency contributors.

    The engine treats trace/service-map structure as strongest topology evidence and
    falls back to edge-labelled metrics/logs/topology when traces are absent or
    incomplete. Timing is necessary but never sufficient: root-contributor ranking
    also uses downstream health, retry amplification, shared-node effects and
    propagation direction. Unknown endpoints remain explicit virtual nodes.
    """
    live_evidence = [item for item in evidence if isinstance(item, Mapping)]
    observations, trace_stats = _collect_edge_observations(live_evidence)
    edges = _aggregate_edges(observations)
    nodes = _node_health(live_evidence, edges)
    fanout = _fanout(edges)
    shared = _shared_dependencies(edges)
    retries = _retry_amplification(edges)
    timeout_propagation = _timeout_propagation(edges)
    cascades = _cascade_chains(edges)
    critical_paths = _critical_paths(edges, service_name)
    roots = _root_contributors(edges, nodes, shared, retries)
    inventory = _dependency_inventory(edges)
    trace = _trace_completeness(trace_stats, observations, live_evidence)
    circuits = _circuit_breakers(edges)

    anomaly_edges = [edge for edge in edges if edge.get("anomaly_start")]
    anomaly_edges.sort(key=lambda edge: edge["anomaly_start"])
    first_failing_edge = None
    if anomaly_edges:
        first = anomaly_edges[0]
        first_failing_edge = {
            "edge_id": first["edge_id"],
            "caller": first["caller"],
            "callee": first["callee"],
            "timestamp": first["anomaly_start"],
            "evidence_ids": first.get("anomaly_evidence_ids", [])[:12],
        }

    propagation_timeline = [
        {
            "timestamp": edge["anomaly_start"],
            "edge_id": edge["edge_id"],
            "caller": edge["caller"],
            "callee": edge["callee"],
            "reasons": edge.get("anomaly_reasons", []),
            "evidence_ids": edge.get("anomaly_evidence_ids", [])[:12],
        }
        for edge in anomaly_edges[:40]
    ]

    missing: List[Dict[str, Any]] = []
    if not edges:
        missing.append({"evidence": "trace or service-map caller-to-callee topology", "information_gain": 1.0})
    if not trace["trace_evidence_present"]:
        missing.append({"evidence": "distributed trace spans for propagation confirmation", "information_gain": 0.98})
    elif trace["trace_completeness"] < 0.80:
        missing.append({"evidence": "complete parent-child trace spans for unresolved or virtual graph segments", "information_gain": 0.97})
    if edges and not any(edge.get("request_rate") is not None for edge in edges):
        missing.append({"evidence": "per-edge request rate", "information_gain": 0.88})
    if edges and not any(edge.get("error_rate") is not None for edge in edges):
        missing.append({"evidence": "per-edge error rate", "information_gain": 0.90})
    if edges and not any(edge.get("latency") is not None for edge in edges):
        missing.append({"evidence": "per-edge latency", "information_gain": 0.86})

    source_counts: Dict[str, int] = defaultdict(int)
    for item in live_evidence:
        source_counts[str(item.get("type") or "unknown").lower()] += 1

    handoffs: List[Dict[str, Any]] = []
    handoff_map = {
        "database": "database",
        "messaging": "messaging",
        "identity": "identity",
        "external_api": "network",
    }
    for root in roots[:6]:
        target = handoff_map.get(str(root.get("dependency_type") or ""))
        if target:
            handoffs.append({
                "agent": target,
                "reason": f"root contributor candidate terminates at {root['dependency_type']} dependency {root['callee']}",
                "evidence_ids": root.get("evidence_ids", [])[:12],
            })
    if inventory["version_or_change"]:
        handoffs.append({
            "agent": "change",
            "reason": "dependency version/change metadata overlaps the dependency graph",
            "evidence_ids": _unique((eid for row in inventory["version_or_change"] for eid in row.get("evidence_ids", [])), 12),
        })

    top_score = float(roots[0]["root_contributor_score"]) if roots else 0.0
    if trace["uncertainty_level"] == "high":
        top_score = min(top_score, 0.55)
    elif trace["uncertainty_level"] == "medium":
        top_score = min(top_score, 0.72)

    return {
        "policy": "directed_dependency_causality_requires_timing_plus_health_and_propagation_evidence; error_volume_alone_never_selects_root_cause",
        "service": service_name,
        "dependency_graph": {
            "directed": True,
            "nodes": nodes[:80],
            "edges": edges[:120],
            "unknown_virtual_nodes": [node for node in nodes if node.get("virtual")][:24],
            "graph_absence_policy": "missing_or_uninstrumented_nodes_are_virtual_unknown_dependencies_not_proof_of_no_dependency",
        },
        "edge_health": edges[:120],
        "fan_out": fanout,
        "shared_dependencies": shared,
        "critical_path_candidates": critical_paths,
        "cascading_failures": cascades,
        "retry_amplification": retries,
        "timeout_propagation": timeout_propagation,
        "circuit_breakers": circuits,
        "dependency_inventory": inventory,
        "first_failing_edge": first_failing_edge,
        "earliest_anomaly": first_failing_edge.get("timestamp") if first_failing_edge else None,
        "propagation_timeline": propagation_timeline,
        "root_contributors": roots,
        "root_contributor_score": round(top_score, 4),
        "trace_completeness": trace,
        "uncertainty_level": trace["uncertainty_level"],
        "confidence_ceiling": trace["confidence_ceiling"],
        "next_best_evidence": sorted(missing, key=lambda row: float(row["information_gain"]), reverse=True)[:10],
        "suggested_handoffs": handoffs[:8],
        "evidence_basis_counts": dict(source_counts),
        "analysis_stages": [
            "trace_and_service_map_normalization",
            "directed_dependency_graph_construction",
            "edge_metric_health_enrichment",
            "unknown_virtual_node_preservation",
            "failure_propagation_timeline",
            "fanout_shared_dependency_and_critical_path_analysis",
            "retry_timeout_and_circuit_breaker_analysis",
            "root_contributor_scoring_with_conflicts",
            "bounded_llm_synthesis",
        ],
        "execution_boundary": "analysis_only",
    }
