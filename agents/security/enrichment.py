from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from agents.security.engine import build_security_analysis


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _eid(item: Mapping[str, Any], index: int) -> str:
    for key in ("evidence_id", "id", "reference", "source_id"):
        if item.get(key) not in (None, ""):
            return str(item[key])
    return f"anonymous:{index}"


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
    for value in (item.get("observed_at"), item.get("timestamp"), item.get("created_at"), raw.get("timestamp"), raw.get("@timestamp")):
        stamp = _parse_time(value)
        if stamp:
            return stamp
    return None


def _scalar(item: Mapping[str, Any], *keys: str) -> Optional[str]:
    raw = _raw(item)
    for source in (item, raw):
        for key in keys:
            value = source.get(key)
            if value not in (None, "") and not isinstance(value, (Mapping, list, tuple)):
                return str(value)[:240]
    return None


def _message(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    value = item.get("message") or raw.get("message") or item.get("name") or raw.get("event") or ""
    text = str(value).strip().lower()
    text = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", text)
    text = re.sub(r"\b\d{4,}\b", "<n>", text)
    text = re.sub(r"\s+", " ", text)
    return text[:420]


def _stable_noise_analysis(items: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for index, item in enumerate(items):
        if str(item.get("type") or "").lower() not in {"log", "event", "alert"}:
            continue
        signature = _message(item)
        if not signature:
            continue
        groups[(str(item.get("source") or "unknown").lower(), signature)].append(_eid(item, index))
    rows = []
    for (source, signature), ids in groups.items():
        if len(ids) < 5:
            continue
        rows.append({
            "explanation": "high-volume duplicate logs can be instrumentation noise or retry amplification rather than independent malicious events",
            "source": source,
            "signature": signature,
            "duplicate_count": len(ids),
            "evidence_ids": ids[:30],
            "verification": "deduplicate by request/session/source and compare unique actors, destinations and successful outcomes",
        })
    rows.sort(key=lambda row: int(row["duplicate_count"]), reverse=True)
    return rows[:6]


def _process_row(item: Mapping[str, Any], index: int) -> Optional[Dict[str, Any]]:
    raw = _raw(item)
    process = raw.get("process") if isinstance(raw.get("process"), Mapping) else {}
    parent = process.get("parent") if isinstance(process.get("parent"), Mapping) else {}
    pid = process.get("pid") or raw.get("pid") or item.get("pid")
    ppid = process.get("ppid") or parent.get("pid") or raw.get("ppid") or raw.get("parent_pid") or item.get("ppid")
    name = process.get("name") or raw.get("process_name") or raw.get("executable") or item.get("process_name")
    executable = process.get("executable") or raw.get("executable") or raw.get("binary_path")
    parent_name = parent.get("name") or raw.get("parent_process") or raw.get("parent_name")
    hash_value = None
    process_hash = process.get("hash") if isinstance(process.get("hash"), Mapping) else {}
    for key in ("sha256", "sha1", "md5"):
        if process_hash.get(key):
            hash_value = f"{key}:{process_hash[key]}"
            break
    hash_value = hash_value or raw.get("process_hash") or raw.get("sha256")
    if not any(value not in (None, "") for value in (pid, ppid, name, executable, parent_name, hash_value)):
        text = _message(item)
        if not any(token in text for token in ("process execution", "process exec", "execve", "unexpected binary", "suspicious process", "process tree")):
            return None
    text = _message(item)
    suspicious = any(token in text for token in ("unexpected binary", "suspicious process", "malicious process", "unsigned binary", "unknown binary"))
    return {
        "evidence_id": _eid(item, index),
        "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
        "asset": _scalar(item, "host", "hostname", "node", "pod", "asset", "instance"),
        "container": _scalar(item, "container", "container_name", "pod"),
        "identity": _scalar(item, "user", "username", "principal", "identity", "service_account"),
        "pid": str(pid) if pid not in (None, "") else None,
        "parent_pid": str(ppid) if ppid not in (None, "") else None,
        "name": str(name)[:240] if name not in (None, "") else None,
        "executable": str(executable)[:320] if executable not in (None, "") else None,
        "parent_name": str(parent_name)[:240] if parent_name not in (None, "") else None,
        "hash": str(hash_value)[:180] if hash_value not in (None, "") else None,
        "signer": _scalar(item, "signer", "signature_status", "package", "package_name"),
        "suspicious_observation": suspicious,
    }


def build_process_tree_analysis(evidence: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    rows = [row for index, item in enumerate(items) if (row := _process_row(item, index)) is not None]
    by_asset_pid: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        if row.get("pid"):
            by_asset_pid[(str(row.get("asset") or "unknown"), str(row["pid"]))] = row
    edges: List[Dict[str, Any]] = []
    missing_parent_refs: List[Dict[str, Any]] = []
    for row in rows:
        if not row.get("parent_pid"):
            continue
        key = (str(row.get("asset") or "unknown"), str(row["parent_pid"]))
        parent = by_asset_pid.get(key)
        if parent:
            edges.append({
                "asset": row.get("asset"),
                "parent_pid": parent.get("pid"),
                "parent_name": parent.get("name"),
                "child_pid": row.get("pid"),
                "child_name": row.get("name"),
                "evidence_ids": list(dict.fromkeys([str(parent.get("evidence_id")), str(row.get("evidence_id"))])),
            })
        else:
            missing_parent_refs.append({
                "asset": row.get("asset"), "child_pid": row.get("pid"), "child_name": row.get("name"),
                "unresolved_parent_pid": row.get("parent_pid"), "parent_name_hint": row.get("parent_name"),
                "evidence_id": row.get("evidence_id"),
            })
    return {
        "policy": "process topology is an observed telemetry structure; unexpected/malicious attribution requires provenance or corroborating evidence",
        "process_count": len(rows),
        "processes": rows[:60],
        "parent_child_edges": edges[:60],
        "unresolved_parent_references": missing_parent_refs[:30],
        "suspicious_process_evidence_ids": [str(row["evidence_id"]) for row in rows if row.get("suspicious_observation")][:30],
    }


def _domain_tags(item: Mapping[str, Any]) -> Set[str]:
    text = _message(item)
    source = str(item.get("source") or "").lower()
    tags: Set[str] = set()
    if any(token in text for token in ("login", "auth", "401", "403", "forbidden", "token", "jwt", "rbac", "identity")) or source in {"identity", "idp", "oidc"}:
        tags.add("identity")
    if any(token in text for token in ("tcp", "dns", "network", "connection", "outbound", "destination", "port", "flow", "reset", "timeout")) or source in {"network", "flow", "netflow"}:
        tags.add("network")
    if any(token in text for token in ("http", "request", "response", "5xx", "4xx", "application", "endpoint", "exception")) or source in {"application", "apm"}:
        tags.add("application")
    return tags


def build_cross_domain_timeline_correlations(
    evidence: Iterable[Mapping[str, Any]], *, window_seconds: int = 300
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        stamp = _timestamp(item)
        if not stamp:
            continue
        tags = _domain_tags(item)
        if not tags:
            continue
        rows.append({
            "evidence_id": _eid(item, index),
            "timestamp": stamp,
            "domains": sorted(tags),
            "identity": _scalar(item, "user", "username", "principal", "identity", "service_account", "subject"),
            "asset": _scalar(item, "host", "hostname", "node", "pod", "asset", "instance"),
            "service": _scalar(item, "service", "service_name", "application", "app", "workload"),
            "source_ip": _scalar(item, "source_ip", "src_ip", "client_ip", "remote_ip"),
        })
    rows.sort(key=lambda row: row["timestamp"])
    correlations: List[Dict[str, Any]] = []
    for left_index, left in enumerate(rows):
        for right in rows[left_index + 1:]:
            delta = (right["timestamp"] - left["timestamp"]).total_seconds()
            if delta > window_seconds:
                break
            if set(left["domains"]) == set(right["domains"]):
                continue
            shared = [
                key for key in ("identity", "asset", "service", "source_ip")
                if left.get(key) and right.get(key) and left.get(key) == right.get(key)
            ]
            if not shared:
                continue
            correlations.append({
                "evidence_ids": [left["evidence_id"], right["evidence_id"]],
                "domains": sorted(set(left["domains"]) | set(right["domains"])),
                "shared_dimensions": shared,
                "delta_seconds": delta,
                "left_timestamp": left["timestamp"].isoformat(),
                "right_timestamp": right["timestamp"].isoformat(),
            })
            if len(correlations) >= 60:
                break
        if len(correlations) >= 60:
            break
    three_domain = [row for row in correlations if {"identity", "network", "application"}.issubset(set(row["domains"]))]
    return {
        "policy": "temporal and scope overlap supports investigation ordering, not causal or malicious attribution",
        "window_seconds": window_seconds,
        "correlations": correlations,
        "identity_network_application_correlations": three_domain,
        "correlation_count": len(correlations),
    }


def _identity_behavior(evidence: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    stats: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: {"sources": set(), "assets": set(), "services": set(), "evidence_ids": set()})
    for index, item in enumerate(evidence):
        identity = _scalar(item, "user", "username", "principal", "identity", "service_account", "subject")
        if not identity:
            continue
        row = stats[identity]
        source = _scalar(item, "source_ip", "src_ip", "client_ip", "remote_ip")
        asset = _scalar(item, "host", "hostname", "node", "pod", "asset", "instance")
        service = _scalar(item, "service", "service_name", "application", "app", "workload")
        if source: row["sources"].add(source)
        if asset: row["assets"].add(asset)
        if service: row["services"].add(service)
        row["evidence_ids"].add(_eid(item, index))
    result = []
    for identity, row in stats.items():
        result.append({
            "identity": identity,
            "unique_source_count": len(row["sources"]),
            "asset_count": len(row["assets"]),
            "service_count": len(row["services"]),
            "sources": sorted(row["sources"])[:20],
            "assets": sorted(row["assets"])[:20],
            "services": sorted(row["services"])[:20],
            "evidence_ids": sorted(row["evidence_ids"])[:30],
            "anomaly_status": "requires_baseline_comparison" if len(row["sources"]) > 1 or len(row["assets"]) > 1 else "insufficient_baseline_for_anomaly_claim",
        })
    result.sort(key=lambda row: (row["unique_source_count"], row["asset_count"], row["service_count"]), reverse=True)
    return result[:30]


def build_security_incident_analysis(
    evidence: Iterable[Mapping[str, Any]], *, service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    result = build_security_analysis(items, service_name=service_name, context=context)
    existing_false_positives = list(result.get("false_positive_analysis") or [])
    signatures = {
        (str(row.get("explanation")), tuple(str(x) for x in row.get("evidence_ids") or []))
        for row in existing_false_positives if isinstance(row, Mapping)
    }
    for row in _stable_noise_analysis(items):
        key = (str(row.get("explanation")), tuple(str(x) for x in row.get("evidence_ids") or []))
        if key not in signatures:
            existing_false_positives.append(row)
            signatures.add(key)
    result["false_positive_analysis"] = existing_false_positives[:8]
    result["process_tree_analysis"] = build_process_tree_analysis(items)
    result["cross_domain_timeline_correlation"] = build_cross_domain_timeline_correlations(items)
    result["identity_behavior_scope"] = _identity_behavior(items)
    result["analysis_stages"] = [
        "security_signal_normalization",
        "auth_authz_and_runtime_features",
        "process_tree_analysis",
        "network_scope_and_scan_aggregation",
        "identity_network_application_timeline_correlation",
        "false_positive_analysis",
        "evidence_threshold_classification",
        "llm_synthesis_bounded_by_deterministic_classification",
    ]
    return result
