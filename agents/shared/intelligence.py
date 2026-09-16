from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


SENSITIVE_KEY_TOKENS = (
    "authorization", "password", "passwd", "secret", "private_key", "privatekey",
    "access_token", "refresh_token", "id_token", "client_secret", "api_key", "apikey",
    "credential", "cookie", "set-cookie",
)

DOMAIN_PLAYBOOKS: Dict[str, Dict[str, List[str]]] = {
    "triage": {
        "checks": ["signal normalization", "temporal ordering", "asset identity", "topology overlap", "blast radius", "evidence gaps"],
        "next": ["alert", "metric", "log", "telemetry", "event"],
    },
    "application": {
        "checks": ["RED rate/error/duration", "p50/p90/p95/p99 tail latency", "HTTP status families", "error signatures", "thread/connection pools", "GC/memory", "dependency contribution", "release/config correlation", "SLO burn"],
        "next": ["metric", "log", "trace", "change"],
    },
    "infrastructure": {
        "checks": ["USE utilization/saturation/errors", "CPU load/run queue/iowait/steal", "memory/swap/page faults/PSI", "disk await/queue/IOPS/inodes", "kernel/system pressure", "capacity trend"],
        "next": ["metric", "telemetry", "log"],
    },
    "kubernetes": {
        "checks": ["Pod/controller state", "rollout generations", "scheduling", "probes", "OOM/evictions", "Service/Endpoint", "PVC/PV", "HPA/PDB", "NetworkPolicy", "event chronology"],
        "next": ["event", "metric", "log"],
    },
    "security": {
        "checks": ["auth/authz trend", "process/runtime events", "source/destination anomalies", "policy denials", "identity/network timeline", "benign alternatives"],
        "next": ["log", "event", "telemetry"],
    },
    "vm": {
        "checks": ["host reachability", "OS pressure", "service state", "process state", "listener", "local TCP", "remote TCP", "DNS/path", "journal/kernel chronology"],
        "next": ["telemetry", "log", "metric"],
    },
    "database": {
        "checks": ["connections/pool", "query latency/fingerprints", "locks/deadlocks/waits", "transactions", "replication", "WAL/checkpoints", "CPU/memory", "storage latency"],
        "next": ["metric", "log", "query_stats"],
    },
    "network": {
        "checks": ["L2/L3 interface/route", "L4 connect/retransmit/reset", "DNS", "TLS/L7 when evidenced", "capacity/conntrack", "source-destination path"],
        "next": ["metric", "telemetry", "log"],
    },
    "storage": {
        "checks": ["capacity/growth", "inode pressure", "IOPS/throughput", "latency/queue", "device/filesystem errors", "mount state", "PV symptoms", "distributed storage health"],
        "next": ["metric", "telemetry", "log"],
    },
    "identity": {
        "checks": ["401 vs 403", "OIDC discovery", "issuer/audience/algorithm", "JWKS rotation/reachability", "token exp/nbf", "clock skew", "roles/scopes", "certificate/TLS"],
        "next": ["log", "metric", "telemetry"],
    },
    "change": {
        "checks": ["deployment/config timeline", "before/after deltas", "scope overlap", "canary/stable comparison", "alternative causes", "rollback-candidate evidence"],
        "next": ["log", "metric", "change"],
    },
    "dependency": {
        "checks": ["directed service graph", "first failing edge", "critical path", "fan-out", "shared dependency", "retry amplification", "timeout propagation", "unknown nodes"],
        "next": ["trace", "metric", "log"],
    },
    "messaging": {
        "checks": ["broker reachability", "queue depth trend", "consumer lag derivative", "producer/consumer errors", "retry/DLQ", "partition/replication", "storage/network pressure"],
        "next": ["metric", "log", "telemetry"],
    },
    "recovery": {
        "checks": ["backup freshness", "verified restore point", "coverage/retention", "replication continuity", "RPO", "RTO readiness", "restore test history", "recovery dependency order"],
        "next": ["log", "metric", "event"],
    },
}

DOMAIN_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "application": ("5xx", "500", "exception", "timeout", "latency", "thread pool", "connection pool", "gc", "endpoint", "retry"),
    "infrastructure": ("cpu", "load", "iowait", "steal", "memory", "swap", "oom", "psi", "inode", "disk", "conntrack"),
    "kubernetes": ("crashloop", "oomkilled", "pending", "failedscheduling", "probe", "evict", "pvc", "endpoint", "rollout", "networkpolicy"),
    "security": ("denied", "unauthorized", "forbidden", "suspicious", "privilege", "malware", "scan", "auth", "policy"),
    "vm": ("systemd", "service", "process", "listener", "journal", "kernel", "reboot", "boot", "oom", "read-only"),
    "database": ("deadlock", "lock wait", "connection", "replication", "wal", "checkpoint", "slow query", "vacuum", "query"),
    "network": ("packet loss", "retrans", "reset", "nxdomain", "servfail", "dns", "route", "unreachable", "tcp", "tls"),
    "storage": ("inode", "iops", "await", "filesystem", "read-only", "smart", "nvme", "ceph", "osd", "slow ops"),
    "identity": ("401", "403", "oidc", "jwks", "issuer", "audience", "signature", "expired", "certificate", "rbac"),
    "change": ("deploy", "release", "rollout", "config", "feature flag", "migration", "image digest", "jenkins", "version"),
    "dependency": ("upstream", "downstream", "dependency", "span", "trace", "fan-out", "circuit breaker", "retry"),
    "messaging": ("consumer lag", "queue", "dlq", "rebalance", "partition", "isr", "broker", "producer", "consumer"),
    "recovery": ("backup", "restore", "snapshot", "rpo", "rto", "replication", "velero", "restore point"),
}

HANDOFF_HINTS: Dict[str, Tuple[Tuple[Tuple[str, ...], str], ...]] = {
    "application": ((('database', 'sql', 'deadlock', 'connection pool'), 'database'), (('dns', 'reset', 'packet loss'), 'network'), (('downstream', 'upstream', 'dependency'), 'dependency'), (('deploy', 'release', 'config'), 'change')),
    "infrastructure": ((('iowait', 'disk', 'inode'), 'storage'), (('packet', 'dns', 'conntrack'), 'network'), (('guest', 'systemd', 'service'), 'vm')),
    "kubernetes": ((('pvc', 'volume', 'mount'), 'storage'), (('node pressure', 'evict'), 'infrastructure'), (('dns', 'networkpolicy', 'endpoint'), 'network'), (('rollout', 'image', 'config'), 'change')),
    "security": ((('token', 'jwks', 'oidc', 'rbac'), 'identity'), (('source', 'destination', 'scan'), 'network'), (('application', 'endpoint'), 'application')),
    "vm": ((('dns', 'route', 'remote tcp'), 'network'), (('disk', 'inode', 'iowait'), 'storage'), (('cpu', 'memory', 'swap'), 'infrastructure')),
    "database": ((('i/o', 'disk', 'storage'), 'storage'), (('connection storm', 'client'), 'application'), (('dns', 'tcp', 'network'), 'network')),
    "network": ((('listener', 'service'), 'application'), (('dns', 'jwks', 'certificate'), 'identity'), (('host', 'conntrack'), 'infrastructure')),
    "storage": ((('database', 'wal', 'query'), 'database'), (('pvc', 'kubernetes'), 'kubernetes'), (('host', 'iowait'), 'infrastructure')),
    "identity": ((('suspicious', 'credential'), 'security'), (('dns', 'tls'), 'network'), (('401', '403', 'endpoint'), 'application')),
    "change": ((('kubernetes', 'rollout'), 'kubernetes'), (('database', 'migration'), 'database'), (('dependency', 'version'), 'dependency')),
    "dependency": ((('database', 'sql'), 'database'), (('broker', 'queue', 'kafka'), 'messaging'), (('dns', 'tcp'), 'network'), (('oidc', 'jwks'), 'identity')),
    "messaging": ((('disk', 'storage'), 'infrastructure'), (('tcp', 'network'), 'network'), (('consumer', 'producer', 'application'), 'application')),
    "recovery": ((('database', 'wal', 'replication'), 'database'), (('volume', 'snapshot', 'storage'), 'storage'), (('application', 'dependency'), 'application')),
}


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(token in normalized for token in SENSITIVE_KEY_TOKENS)


def sanitize_prompt_value(value: Any, depth: int = 0) -> Any:
    """Bound and redact untrusted operational data before it reaches an LLM prompt."""
    if depth >= 5:
        return "[bounded]"
    if isinstance(value, str):
        value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        return value if len(value) <= 520 else value[:520] + "...[truncated]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [sanitize_prompt_value(item, depth + 1) for item in list(value)[:10]]
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, current in list(value.items())[:40]:
            result[str(key)] = "[REDACTED]" if _is_sensitive_key(key) else sanitize_prompt_value(current, depth + 1)
        return result
    return sanitize_prompt_value(str(value), depth + 1)


def prompt_evidence_projection(evidence: Iterable[Dict[str, Any]], limit: int = 40) -> List[Dict[str, Any]]:
    projected: List[Dict[str, Any]] = []
    for item in list(evidence)[:limit]:
        if not isinstance(item, dict):
            continue
        projected.append(sanitize_prompt_value({
            "id": item.get("evidence_id") or item.get("id") or item.get("reference"),
            "type": item.get("type"),
            "source": item.get("source"),
            "timestamp": item.get("observed_at") or item.get("timestamp") or item.get("created_at"),
            "name": item.get("name"),
            "value": item.get("value"),
            "message": item.get("message"),
            "severity": item.get("severity"),
            "raw_data": item.get("raw_data") or {},
        }))
    return projected


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
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


def _evidence_id(item: Dict[str, Any]) -> Optional[str]:
    raw = item.get("evidence_id") or item.get("id") or item.get("reference")
    return str(raw) if raw else None


def _flatten_text(value: Any, depth: int = 0) -> List[str]:
    if depth >= 4:
        return []
    if isinstance(value, str):
        return [value[:400]]
    if isinstance(value, dict):
        parts: List[str] = []
        for key, current in list(value.items())[:30]:
            if _is_sensitive_key(key):
                continue
            parts.extend(_flatten_text(current, depth + 1))
        return parts
    if isinstance(value, (list, tuple)):
        parts: List[str] = []
        for current in list(value)[:10]:
            parts.extend(_flatten_text(current, depth + 1))
        return parts
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    return []


def _item_text(item: Dict[str, Any]) -> str:
    safe = {key: value for key, value in item.items() if not _is_sensitive_key(key)}
    return " ".join(_flatten_text(safe)).lower()


def _numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        candidate = value.strip().rstrip("%")
        try:
            return float(candidate)
        except ValueError:
            return None
    return None


def _metric_name_value(item: Dict[str, Any]) -> Tuple[Optional[str], Optional[float]]:
    raw = item.get("raw_data") if isinstance(item.get("raw_data"), dict) else {}
    name = item.get("name") or item.get("metric") or raw.get("name") or raw.get("metric") or raw.get("item_key")
    value = item.get("value") if item.get("value") is not None else raw.get("value")
    return (str(name).lower() if name else None, _numeric(value))


def _baseline_delta(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = item.get("raw_data") if isinstance(item.get("raw_data"), dict) else {}
    current = _numeric(item.get("value") if item.get("value") is not None else raw.get("value"))
    baseline = None
    for key in ("baseline", "baseline_value", "previous", "previous_value", "historical", "normal"):
        baseline = _numeric(raw.get(key))
        if baseline is not None:
            break
    if current is None or baseline is None:
        return None
    absolute = current - baseline
    relative = None if baseline == 0 else absolute / abs(baseline)
    return {"current": current, "baseline": baseline, "absolute_delta": round(absolute, 6), "relative_delta": None if relative is None else round(relative, 4)}


def _domain_signals(domain: str, evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    keywords = DOMAIN_KEYWORDS.get(domain, ())
    signals: List[Dict[str, Any]] = []
    for item in evidence:
        text = _item_text(item)
        matched = [keyword for keyword in keywords if keyword in text]
        if matched:
            signals.append({"evidence_id": _evidence_id(item), "matches": matched[:6], "type": item.get("type"), "source": item.get("source")})
        if len(signals) >= 12:
            break
    return signals


def _metric_features(evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    grouped: Dict[str, List[float]] = defaultdict(list)
    deltas: List[Dict[str, Any]] = []
    for item in evidence:
        if str(item.get("type", "")).lower() != "metric":
            continue
        name, value = _metric_name_value(item)
        if name and value is not None:
            grouped[name].append(value)
        delta = _baseline_delta(item)
        if name and delta:
            deltas.append({"metric": name, "evidence_id": _evidence_id(item), **delta})
    summary = {
        name: {"count": len(values), "min": min(values), "max": max(values), "latest": values[-1]}
        for name, values in list(grouped.items())[:24]
    }
    deltas.sort(key=lambda row: abs(row.get("relative_delta") or 0), reverse=True)
    return {"series": summary, "largest_baseline_deltas": deltas[:10]}


def _timeline(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Tuple[datetime, Dict[str, Any]]] = []
    for item in evidence:
        stamp = _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at"))
        if stamp:
            rows.append((stamp, item))
    rows.sort(key=lambda row: row[0])
    return [{
        "timestamp": stamp.isoformat(),
        "evidence_id": _evidence_id(item),
        "type": item.get("type"),
        "source": item.get("source"),
        "name": item.get("name"),
    } for stamp, item in rows[:16]]


def _suggested_handoffs(domain: str, evidence: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    combined = " ".join(_item_text(item) for item in evidence)
    suggestions: List[Dict[str, str]] = []
    seen: set[str] = set()
    for tokens, target in HANDOFF_HINTS.get(domain, ()):
        matched = [token for token in tokens if token in combined]
        if matched and target not in seen:
            suggestions.append({"agent": target, "reason": f"live evidence mentions {', '.join(matched[:3])}"})
            seen.add(target)
    return suggestions[:6]


def _network_paths(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in evidence:
        raw = item.get("raw_data") if isinstance(item.get("raw_data"), dict) else {}
        source = raw.get("source") or raw.get("src") or raw.get("source_host")
        destination = raw.get("destination") or raw.get("dst") or raw.get("target") or item.get("target")
        port = raw.get("port") or raw.get("target_port") or item.get("port")
        protocol = raw.get("protocol")
        if source or destination or port:
            rows.append({"evidence_id": _evidence_id(item), "source": source, "destination": destination, "protocol": protocol, "port": port})
    return rows[:12]


def _topology_edges(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in evidence:
        raw = item.get("raw_data") if isinstance(item.get("raw_data"), dict) else {}
        caller = raw.get("caller") or raw.get("source_service") or raw.get("upstream")
        callee = raw.get("callee") or raw.get("destination_service") or raw.get("downstream")
        if caller and callee:
            rows.append({
                "evidence_id": _evidence_id(item), "caller": caller, "callee": callee,
                "latency": raw.get("latency"), "error_rate": raw.get("error_rate"),
                "timeout": raw.get("timeout"), "retry": raw.get("retry") or raw.get("retries"),
            })
    return rows[:16]


def _kubernetes_objects(evidence: List[Dict[str, Any]]) -> Dict[str, int]:
    kinds = ("pod", "replicaset", "deployment", "statefulset", "daemonset", "job", "cronjob", "node", "service", "endpoint", "ingress", "pvc", "pv", "hpa", "pdb", "networkpolicy")
    counts: Counter[str] = Counter()
    for item in evidence:
        text = _item_text(item)
        for kind in kinds:
            if kind in text:
                counts[kind] += 1
    return dict(counts)


def _security_evidence_level(evidence: List[Dict[str, Any]]) -> str:
    text = " ".join(_item_text(item) for item in evidence)
    direct = ("confirmed compromise", "malware detected", "credential theft confirmed", "exfiltration confirmed")
    suspicious = ("suspicious", "unexpected outbound", "privilege escalation", "scan", "anomalous")
    policy = ("policy deny", "policy violation", "forbidden", "authorization denied")
    if any(token in text for token in direct):
        return "direct_compromise_evidence_present"
    if any(token in text for token in suspicious):
        return "suspicious_event_observed"
    if any(token in text for token in policy):
        return "policy_or_authorization_event_observed"
    return "no_direct_security_conclusion"


def _recovery_points(evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    points: List[Tuple[datetime, str, bool]] = []
    for item in evidence:
        text = _item_text(item)
        if not any(token in text for token in ("backup", "restore", "snapshot", "recovery point")):
            continue
        raw = item.get("raw_data") if isinstance(item.get("raw_data"), dict) else {}
        stamp = _parse_timestamp(raw.get("restore_point") or raw.get("backup_time") or item.get("observed_at") or item.get("timestamp"))
        if stamp:
            verified = bool(raw.get("verified") or raw.get("restore_verified") or raw.get("restore_test_success"))
            points.append((stamp, _evidence_id(item) or "unknown", verified))
    points.sort(reverse=True)
    latest = points[0] if points else None
    verified = next((point for point in points if point[2]), None)
    return {
        "latest_restore_or_backup": latest[0].isoformat() if latest else None,
        "latest_restore_or_backup_evidence_id": latest[1] if latest else None,
        "latest_verified_restore_point": verified[0].isoformat() if verified else None,
        "latest_verified_restore_evidence_id": verified[1] if verified else None,
        "restore_validation_missing": bool(points and verified is None),
    }


def build_deterministic_analysis(
    domain: str,
    evidence: Iterable[Dict[str, Any]],
    required_types: Optional[Iterable[str]] = None,
    service_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Extract bounded, explainable features before LLM synthesis.

    The function intentionally does not declare a root cause. It exposes observed
    features, chronology, gaps and handoff hints so the specialist can reason over
    concrete live evidence instead of asking the LLM to rediscover raw telemetry.
    """
    domain = str(domain).lower()
    items = [item for item in evidence if isinstance(item, dict)]
    type_counts = Counter(str(item.get("type", "unknown")).lower() for item in items)
    source_counts = Counter(str(item.get("source", "unknown")).lower() for item in items)
    required = [str(value).lower() for value in (required_types or [])]
    missing = [value for value in required if type_counts.get(value, 0) == 0]
    playbook = DOMAIN_PLAYBOOKS.get(domain, {"checks": [], "next": ["metric", "log"]})
    next_best = []
    for evidence_type in list(missing) + list(playbook.get("next", [])):
        if evidence_type not in next_best:
            next_best.append(evidence_type)
    signals = _domain_signals(domain, items)
    analysis: Dict[str, Any] = {
        "policy": "deterministic_features_are_observations_not_root_cause; correlation_requires_falsification",
        "domain": domain,
        "service": service_name,
        "evidence_count": len(items),
        "evidence_type_counts": dict(type_counts),
        "evidence_source_counts": dict(source_counts),
        "evidence_gap_matrix": {value: {"present": type_counts.get(value, 0) > 0, "count": type_counts.get(value, 0)} for value in required},
        "missing_required_types": missing,
        "next_best_evidence": next_best[:6],
        "playbook_checks": playbook.get("checks", []),
        "timeline": _timeline(items),
        "metric_features": _metric_features(items),
        "direct_domain_signals": signals,
        "suggested_handoffs": _suggested_handoffs(domain, items),
    }
    if domain in {"network", "vm", "identity", "dependency", "application"}:
        analysis["network_paths"] = _network_paths(items)
    if domain in {"dependency", "application", "change", "triage"}:
        analysis["topology_edges"] = _topology_edges(items)
    if domain == "kubernetes":
        analysis["resource_evidence_counts"] = _kubernetes_objects(items)
    if domain == "security":
        analysis["security_evidence_level"] = _security_evidence_level(items)
    if domain == "recovery":
        analysis["recovery_points"] = _recovery_points(items)
    if domain == "change":
        analysis["candidate_change_evidence_ids"] = [
            _evidence_id(item) for item in items
            if any(token in _item_text(item) for token in DOMAIN_KEYWORDS["change"])
        ][:12]
    if domain == "messaging":
        analysis["lag_or_backlog_signals"] = [row for row in signals if any(token in row["matches"] for token in ("consumer lag", "queue", "dlq", "rebalance"))][:10]
    if domain == "identity":
        analysis["redaction_policy"] = "tokens_credentials_private_keys_and_authorization_headers_are_redacted_before_prompting"
    return sanitize_prompt_value(analysis)
