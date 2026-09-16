from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _field(item: Mapping[str, Any], keys: Sequence[str]) -> Any:
    labels = _raw(item).get("labels")
    sources = (item, _raw(item), labels if isinstance(labels, Mapping) else {})
    for source in sources:
        for key in keys:
            value = source.get(key)
            if value not in (None, ""):
                return value
    return None


def _eid(item: Mapping[str, Any], index: int) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _parse_ts(value: Any) -> Optional[datetime]:
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
    return _parse_ts(
        item.get("observed_at")
        or item.get("timestamp")
        or item.get("created_at")
        or _raw(item).get("timestamp")
    )


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _numeric(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        candidate = value.strip().lower().replace(",", "")
        if candidate.endswith("%"):
            candidate = candidate[:-1]
        if candidate.endswith("ms"):
            candidate = candidate[:-2]
        try:
            return float(candidate.strip())
        except ValueError:
            return None
    return None


def _bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        value = value.strip().lower()
        if value in {"true", "yes", "1", "up", "healthy", "available", "reachable", "running", "ok"}:
            return True
        if value in {"false", "no", "0", "down", "unhealthy", "unavailable", "unreachable", "failed", "stopped"}:
            return False
    return None


def _unique(values: Iterable[Any], limit: int = 24) -> List[str]:
    output: List[str] = []
    for raw in values:
        if raw in (None, ""):
            continue
        value = str(raw).strip()
        if value and value not in output:
            output.append(value)
        if len(output) >= limit:
            break
    return output


def _text(item: Mapping[str, Any]) -> str:
    parts: List[str] = []
    for source in (item, _raw(item)):
        for key, value in list(source.items())[:50]:
            normalized = str(key).lower()
            if any(token in normalized for token in ("secret", "password", "authorization", "token", "credential", "private_key")):
                continue
            if isinstance(value, str):
                parts.append(value[:400])
            elif isinstance(value, (int, float, bool)):
                parts.append(str(value))
    return " ".join(parts).lower()


def _metric_name(item: Mapping[str, Any]) -> str:
    return str(
        item.get("name")
        or item.get("metric")
        or _raw(item).get("name")
        or _raw(item).get("metric")
        or _raw(item).get("item_key")
        or ""
    ).lower()


def _metric_value(item: Mapping[str, Any]) -> Optional[float]:
    raw = _raw(item)
    value = item.get("value") if item.get("value") is not None else raw.get("value")
    return _numeric(value)


def _baseline(item: Mapping[str, Any]) -> Optional[float]:
    raw = _raw(item)
    for key in ("baseline", "baseline_value", "previous", "previous_value", "historical", "normal", "pre_incident"):
        value = _numeric(raw.get(key))
        if value is not None:
            return value
    return None


def _kind(name: str) -> Optional[str]:
    rules = (
        ("consumer_lag", ("consumer_lag", "records_lag", "kafka_lag", "lag_messages")),
        ("message_age", ("message_age", "oldest_message_age", "record_age")),
        ("under_replicated", ("under_replicated", "underreplicated")),
        ("offline_partitions", ("offline_partition",)),
        ("leader_imbalance", ("leader_imbalance", "leader_skew")),
        ("isr_shrink", ("isr_shrink", "isr_shrinks")),
        ("isr_expand", ("isr_expand", "isr_expands")),
        ("producer_errors", ("producer_error", "produce_error")),
        ("consumer_errors", ("consumer_error", "consume_error")),
        ("rebalance", ("rebalance",)),
        ("queue_depth", ("queue_depth", "messages_ready", "backlog")),
        ("publish_rate", ("publish_rate", "producer_rate", "messages_in", "produced_rate")),
        ("consume_rate", ("consume_rate", "consumer_rate", "messages_out", "consumed_rate")),
        ("ack_rate", ("ack_rate", "acknowledge_rate")),
        ("ack_latency", ("ack_latency", "acknowledgement_latency")),
        ("unacked", ("unacked", "messages_unacknowledged")),
        ("retry", ("retry_rate", "retries")),
        ("dlq", ("dlq", "dead_letter")),
        ("redelivery", ("redelivery", "redelivered")),
        ("broker_disk", ("broker_disk", "disk_util", "disk_usage")),
        ("disk_latency", ("disk_latency", "disk_await", "io_wait")),
        ("network", ("broker_network", "network_error", "network_latency")),
        ("broker_reachable", ("broker_reachable", "broker_up", "broker_available")),
        ("broker_failure", ("broker_failure", "broker_errors", "broker_down")),
        ("controller", ("controller", "active_controller")),
        ("leader", ("leader_count", "leader_election", "leader_missing")),
        ("replication", ("replication", "replica_state")),
        ("throughput", ("throughput", "bytes_in", "bytes_out")),
    )
    for kind, tokens in rules:
        if any(token in name for token in tokens):
            return kind
    return None


def _dim(item: Mapping[str, Any], keys: Sequence[str], default: str) -> str:
    value = _field(item, keys)
    return str(value)[:180] if value not in (None, "") else default


def _row(item: Mapping[str, Any], index: int) -> Dict[str, Any]:
    name = _metric_name(item)
    kind = _kind(name)
    text = _text(item)
    value = _metric_value(item)
    reachable = _bool(_field(item, ("reachable", "broker_reachable", "available", "up")))
    if kind == "broker_reachable" and value is not None:
        reachable = bool(value)
    return {
        "evidence_id": _eid(item, index),
        "timestamp": _timestamp(item),
        "source": str(item.get("source") or "unknown"),
        "kind": kind,
        "name": name,
        "value": value,
        "baseline": _baseline(item),
        "broker": _dim(item, ("broker", "broker_id", "node", "host", "instance"), "unknown"),
        "topic": _dim(item, ("topic", "queue", "destination", "stream"), "unknown"),
        "partition": _dim(item, ("partition", "partition_id"), "all"),
        "group": _dim(item, ("consumer_group", "group", "group_id", "consumer"), "unknown"),
        "application": _dim(item, ("application", "service", "service_name", "client_id"), "unknown"),
        "reachable": reachable,
        "broker_failure_signal": (
            (kind == "broker_failure" and value is not None and value > 0)
            or any(token in text for token in ("broker unavailable", "broker down", "controller unavailable", "leader not available", "no leader"))
        ),
        "consumer_crash_signal": any(token in text for token in ("consumer crashed", "consumer process exited", "consumer stopped unexpectedly")),
        "poison_signal": any(token in text for token in ("poison message", "deserialization failed", "retry loop", "repeated delivery")),
        "downstream_signal": any(token in text for token in ("downstream unavailable", "downstream timeout", "application dependency failed")),
    }


def _latest(rows: List[Dict[str, Any]], kind: str) -> Optional[Dict[str, Any]]:
    matches = [row for row in rows if row.get("kind") == kind and row.get("value") is not None]
    if not matches:
        return None
    matches.sort(key=lambda row: row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc))
    return matches[-1]


def _series(rows: List[Dict[str, Any]], kind: str, dims: Sequence[str]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[str, ...], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("kind") == kind and row.get("value") is not None:
            groups[tuple(str(row.get(dim) or "unknown") for dim in dims)].append(row)
    output: List[Dict[str, Any]] = []
    for key, samples in groups.items():
        samples.sort(key=lambda row: row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc))
        first, last = samples[0], samples[-1]
        delta = float(last["value"]) - float(first["value"])
        derivative = None
        seconds = None
        if first.get("timestamp") and last.get("timestamp") and last["timestamp"] > first["timestamp"]:
            seconds = (last["timestamp"] - first["timestamp"]).total_seconds()
            derivative = delta / seconds
        elif last.get("baseline") is not None:
            delta = float(last["value"]) - float(last["baseline"])
        output.append({
            **{dims[i]: key[i] for i in range(len(dims))},
            "first": float(first["value"]),
            "latest": float(last["value"]),
            "delta": round(delta, 6),
            "derivative_per_second": None if derivative is None else round(derivative, 6),
            "window_seconds": seconds,
            "start": _iso(first.get("timestamp")),
            "end": _iso(last.get("timestamp")),
            "evidence_ids": _unique(row["evidence_id"] for row in samples),
        })
    output.sort(key=lambda row: abs(float(row["delta"])), reverse=True)
    return output[:30]


def _broker(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    reaches = [row for row in rows if row.get("reachable") is not None]
    reaches.sort(key=lambda row: row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc))
    latest_reach = reaches[-1] if reaches else None
    failures = [row for row in rows if row["broker_failure_signal"]]
    values: Dict[str, Any] = {}
    ids: List[str] = []
    for kind in ("offline_partitions", "under_replicated", "controller", "leader", "replication", "broker_disk", "disk_latency", "network"):
        row = _latest(rows, kind)
        values[kind] = row.get("value") if row else None
        if row:
            ids.append(row["evidence_id"])
    return {
        "reachable": latest_reach.get("reachable") if latest_reach else None,
        "reachability_evidence_ids": [latest_reach["evidence_id"]] if latest_reach else [],
        "failure_evidence_ids": _unique(row["evidence_id"] for row in failures),
        **values,
        "evidence_ids": _unique([*ids, *(row["evidence_id"] for row in failures), *([] if latest_reach is None else [latest_reach["evidence_id"]])]),
    }


def _partitions(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    latest: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        if row.get("kind") != "throughput" or row.get("partition") in {"all", "unknown"} or row.get("value") is None:
            continue
        key = (row["topic"], row["partition"])
        current = latest.get(key)
        if current is None or (row.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc)) >= (current.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc)):
            latest[key] = row
    by_topic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for (topic, _), row in latest.items():
        by_topic[topic].append(row)
    hot: List[Dict[str, Any]] = []
    for topic, samples in by_topic.items():
        values = [float(row["value"]) for row in samples]
        if len(values) < 2 or sum(values) <= 0:
            continue
        mean = sum(values) / len(values)
        for row in samples:
            skew = float(row["value"]) / mean
            if skew >= 2.0:
                hot.append({
                    "topic": topic, "partition": row["partition"], "throughput": row["value"],
                    "mean_partition_throughput": round(mean, 6), "skew_ratio": round(skew, 4),
                    "evidence_ids": [row["evidence_id"]],
                })
    hot.sort(key=lambda row: row["skew_ratio"], reverse=True)
    leader = _latest(rows, "leader_imbalance")
    return {
        "hot_partitions": hot[:12],
        "leader_imbalance": leader.get("value") if leader else None,
        "leader_imbalance_evidence_ids": [leader["evidence_id"]] if leader else [],
    }


def _candidate(cause: str, confidence: float, evidence_ids: Iterable[str], reason: str, checks: Sequence[str], conflicts: Iterable[str] = ()) -> Dict[str, Any]:
    return {
        "cause": cause,
        "confidence": round(max(0.0, min(0.95, confidence)), 4),
        "status": "candidate_requires_falsification",
        "reason": reason,
        "supporting_evidence_ids": _unique(evidence_ids, 16),
        "conflicting_evidence": _unique(conflicts, 12),
        "falsification_checks": list(checks)[:6],
    }


def _candidates(rows: List[Dict[str, Any]], broker: Dict[str, Any], lag: List[Dict[str, Any]], depth: List[Dict[str, Any]], dlq: List[Dict[str, Any]], partitions: Dict[str, Any]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    publish, consume = _latest(rows, "publish_rate"), _latest(rows, "consume_rate")
    retry, redelivery = _latest(rows, "retry"), _latest(rows, "redelivery")
    consumer_errors = _latest(rows, "consumer_errors")
    crash = [row for row in rows if row["consumer_crash_signal"]]
    poison = [row for row in rows if row["poison_signal"]]
    downstream = [row for row in rows if row["downstream_signal"]]
    network = [row for row in rows if row.get("kind") == "network" and (row.get("value") or 0) > 0]
    storage = [
        row for row in rows
        if (row.get("kind") == "broker_disk" and (row.get("value") or 0) >= 90)
        or (row.get("kind") == "disk_latency" and (row.get("value") or 0) >= 20)
    ]

    if broker["reachable"] is False or broker["failure_evidence_ids"] or (broker.get("offline_partitions") or 0) > 0:
        output.append(_candidate(
            "broker_failure", 0.84 if broker["reachable"] is False else 0.72, broker["evidence_ids"],
            "direct broker unreachability/failure or offline-partition evidence",
            ("verify broker/controller reachability from multiple clients", "confirm leader/controller and replica state", "check whether client network path alone explains failures"),
        ))

    lag_up = [row for row in lag if row["delta"] > 0]
    publish_value = float(publish["value"]) if publish else None
    consume_value = float(consume["value"]) if consume else None
    publish_baseline = float(publish["baseline"]) if publish and publish.get("baseline") is not None else None
    surge = bool(publish and (
        (publish_baseline is not None and publish_value is not None and publish_value > max(publish_baseline * 1.5, publish_baseline + 1))
        or (publish_value is not None and consume_value is not None and publish_value > consume_value * 1.25)
    ))
    if surge:
        output.append(_candidate(
            "producer_surge", 0.74, [publish["evidence_id"], *(eid for row in depth if row["delta"] > 0 for eid in row["evidence_ids"])],
            "publish rate increased materially versus baseline or consume capacity",
            ("compare producer rate with baseline", "verify consumer capacity remained stable", "check whether broker/storage/network degraded first"),
        ))
    if crash and lag_up:
        output.append(_candidate(
            "crashed_consumer", 0.86, [*(row["evidence_id"] for row in crash), *(eid for trend in lag_up for eid in trend["evidence_ids"])],
            "consumer crash evidence coincides with increasing lag",
            ("verify consumer process/group membership", "confirm consume rate dropped after crash", "check broker partition availability"),
        ))
    elif lag_up:
        slow = consume_value is not None and publish_value is not None and consume_value < publish_value
        output.append(_candidate(
            "slow_consumer", 0.78 if slow else 0.64, (eid for trend in lag_up for eid in trend["evidence_ids"]),
            "consumer lag derivative is positive; trend is stronger evidence than a lag snapshot",
            ("measure consume rate and handler latency", "compare lag derivative before/after consumer recovery", "verify downstream application latency"),
        ))

    dlq_up = [row for row in dlq if row["delta"] > 0]
    if (poison or dlq_up) and ((retry and (retry["value"] or 0) > 0) or (redelivery and (redelivery["value"] or 0) > 0) or dlq_up):
        output.append(_candidate(
            "poison_message_retry_loop", 0.82,
            [*(row["evidence_id"] for row in poison), *(eid for trend in dlq_up for eid in trend["evidence_ids"]), *([] if retry is None else [retry["evidence_id"]]), *([] if redelivery is None else [redelivery["evidence_id"]])],
            "DLQ/retry/redelivery growth is corroborated by poison/repeated-delivery evidence",
            ("compare normalized failure signatures", "verify few message keys dominate retries", "check downstream outage as alternative"),
        ))

    if storage:
        output.append(_candidate(
            "storage_pressure", 0.80, (row["evidence_id"] for row in storage),
            "broker disk utilization/latency can explain broker latency",
            ("compare broker latency with disk await/utilization timeline", "verify network did not degrade first", "check broker flush/disk logs"),
        ))
    if network and not storage:
        output.append(_candidate(
            "network_problem", 0.70, (row["evidence_id"] for row in network),
            "broker/client network telemetry degraded without stronger storage evidence",
            ("compare multiple source-to-broker paths", "verify broker-local health/listener", "check loss/retransmission/DNS"),
        ))
    if partitions["hot_partitions"] or (partitions.get("leader_imbalance") or 0) > 0:
        output.append(_candidate(
            "partition_skew", 0.76,
            [*(eid for row in partitions["hot_partitions"] for eid in row["evidence_ids"]), *partitions["leader_imbalance_evidence_ids"]],
            "per-partition throughput or leader placement is materially skewed",
            ("compare hot partition with siblings", "verify key distribution/leader placement", "check localized broker pressure"),
        ))
    if downstream or (consumer_errors and broker["reachable"] is not False):
        output.append(_candidate(
            "downstream_application_failure", 0.68 if downstream else 0.55,
            [*(row["evidence_id"] for row in downstream), *([] if consumer_errors is None else [consumer_errors["evidence_id"]])],
            "consumer/downstream errors exist while broker failure is not independently established",
            ("verify downstream application health", "confirm broker fetch/produce path is healthy", "compare dependency failure timing"),
            ("broker_unreachable",) if broker["reachable"] is False else (),
        ))

    output.sort(key=lambda row: row["confidence"], reverse=True)
    return output[:12]


def build_messaging_reliability_analysis(
    evidence: List[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    live = [item for item in evidence if isinstance(item, Mapping)]
    rows = [_row(item, index) for index, item in enumerate(live)]
    broker = _broker(rows)
    lag = _series(rows, "consumer_lag", ("topic", "group"))
    depth = _series(rows, "queue_depth", ("topic",))
    dlq = _series(rows, "dlq", ("topic",))
    age = _series(rows, "message_age", ("topic",))
    partitions = _partitions(rows)
    candidates = _candidates(rows, broker, lag, depth, dlq, partitions)

    latest = {}
    for kind in ("publish_rate", "consume_rate", "ack_rate", "ack_latency", "unacked", "retry", "redelivery", "producer_errors", "consumer_errors", "rebalance", "isr_shrink", "isr_expand"):
        row = _latest(rows, kind)
        latest[kind] = row.get("value") if row else None

    serious = {"broker_failure", "crashed_consumer", "storage_pressure", "network_problem", "poison_message_retry_loop"}
    backlog_healthy = (
        broker["reachable"] is not False
        and bool(depth)
        and all(row["delta"] <= 0 for row in depth)
        and (not lag or all(row["delta"] <= 0 for row in lag))
        and not any(row["cause"] in serious and row["confidence"] >= 0.6 for row in candidates)
    )
    healthy_backlog = {
        "status": "healthy_transient_backlog" if backlog_healthy else "not_established",
        "queue_depth_high_alone_is_broker_failure": False,
        "reason": "backlog is draining/non-growing with no stronger broker/storage/network failure" if backlog_healthy else "transient healthy backlog not established",
    }

    missing: List[Dict[str, Any]] = []
    if broker["reachable"] is None:
        missing.append({"evidence": "broker reachability/controller health", "information_gain": 1.0})
    if not lag:
        missing.append({"evidence": "consumer lag time series with at least two samples", "information_gain": 0.98})
    if latest["publish_rate"] is None or latest["consume_rate"] is None:
        missing.append({"evidence": "publish and consume rates for the same incident window", "information_gain": 0.94})
    if broker["broker_disk"] is None and broker["disk_latency"] is None:
        missing.append({"evidence": "broker disk utilization/latency", "information_gain": 0.86})
    if broker["network"] is None:
        missing.append({"evidence": "source-to-broker network telemetry", "information_gain": 0.82})

    cause_to_agent = {
        "slow_consumer": "application", "crashed_consumer": "application", "producer_surge": "application",
        "poison_message_retry_loop": "application", "network_problem": "network", "storage_pressure": "infrastructure",
        "partition_skew": "infrastructure", "broker_failure": "infrastructure", "downstream_application_failure": "dependency",
    }
    handoffs: List[Dict[str, Any]] = []
    for candidate in candidates:
        target = cause_to_agent.get(candidate["cause"])
        if target and target not in {row["agent"] for row in handoffs}:
            handoffs.append({
                "agent": target,
                "reason": f"messaging candidate {candidate['cause']} requires cross-domain falsification",
                "evidence_ids": candidate["supporting_evidence_ids"],
            })
    if any(candidate["cause"] == "downstream_application_failure" for candidate in candidates) and "application" not in {row["agent"] for row in handoffs}:
        handoffs.append({"agent": "application", "reason": "consumer handler health requires independent application verification", "evidence_ids": []})

    sources = {row["source"] for row in rows}
    ceiling = 0.90 if len(sources) > 1 else 0.78
    if broker["reachable"] is None or not lag:
        ceiling = min(ceiling, 0.68)

    return {
        "policy": "queue_depth_or_single_lag_snapshot_never_proves_broker_failure; lag_derivative_and_cross_layer_corroboration_are_required",
        "service": service_name,
        "broker": broker,
        "kafka": {
            "consumer_lag": lag,
            "message_age": age,
            "under_replicated_partitions": broker["under_replicated"],
            "offline_partitions": broker["offline_partitions"],
            "leader_imbalance": partitions["leader_imbalance"],
            "isr_shrink": latest["isr_shrink"],
            "isr_expand": latest["isr_expand"],
            "producer_errors": latest["producer_errors"],
            "consumer_errors": latest["consumer_errors"],
            "rebalance_frequency": latest["rebalance"],
            "hot_partitions": partitions["hot_partitions"],
        },
        "queue_systems": {
            "queue_depth": depth,
            "publish_rate": latest["publish_rate"],
            "consume_rate": latest["consume_rate"],
            "ack_rate": latest["ack_rate"],
            "ack_latency": latest["ack_latency"],
            "unacked_messages": latest["unacked"],
            "retry_rate": latest["retry"],
            "dlq_growth": dlq,
            "redelivery": latest["redelivery"],
            "oldest_message_age": age,
        },
        "lag_trends": lag,
        "queue_depth_trends": depth,
        "partition_distribution": partitions,
        "cause_candidates": candidates,
        "healthy_backlog_assessment": healthy_backlog,
        "suggested_handoffs": handoffs[:8],
        "next_best_evidence": sorted(missing, key=lambda row: row["information_gain"], reverse=True)[:8],
        "source_counts": {source: sum(1 for row in rows if row["source"] == source) for source in sorted(sources)},
        "confidence_ceiling": ceiling,
        "explainable_confidence": {
            "ceiling": ceiling,
            "factors": ["multi-source corroboration", "lag/backlog derivative", "broker reachability", "storage/network counter-evidence", "application/dependency alternatives"],
        },
        "execution_boundary": "analysis_only",
    }
