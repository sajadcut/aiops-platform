from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


DOMAINS: Tuple[str, ...] = (
    "application", "infrastructure", "kubernetes", "security", "vm",
    "database", "network", "storage", "identity", "change",
    "dependency", "messaging", "recovery",
)

DOMAIN_REQUIREMENTS: Dict[str, Tuple[str, ...]] = {
    "application": ("metric", "log"),
    "infrastructure": ("metric", "telemetry"),
    "kubernetes": ("event", "metric"),
    "security": ("log", "event"),
    "vm": ("telemetry", "log"),
    "database": ("metric", "log"),
    "network": ("metric", "telemetry"),
    "storage": ("metric", "telemetry"),
    "identity": ("log", "metric"),
    "change": ("event", "log"),
    "dependency": ("metric", "log"),
    "messaging": ("metric", "log"),
    "recovery": ("log", "event"),
}

DOMAIN_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "application": ("500", "5xx", "exception", "timeout", "latency", "http", "endpoint", "thread pool", "connection pool", "retry"),
    "infrastructure": ("cpu", "memory", "load", "iowait", "steal", "swap", "oom", "psi", "conntrack", "node pressure"),
    "kubernetes": ("pod", "deployment", "statefulset", "crashloop", "pending", "failedscheduling", "probe", "evict", "kubernetes", "k8s"),
    "security": ("suspicious", "malware", "privilege", "attack", "scan", "exfiltration", "policy deny", "compromise"),
    "vm": ("systemd", "service down", "service failed", "process", "listener", "journal", "kernel", "host unreachable", "vm"),
    "database": ("database", "postgres", "mysql", "oracle", "sql", "deadlock", "lock wait", "connection exhaustion", "too many connections", "pg_stat", "replication lag", "wal"),
    "network": ("packet loss", "retransmit", "reset", "connection refused", "connection timed out", "route", "unreachable", "network path", "tcp", "dns", "nxdomain", "servfail"),
    "storage": ("pvc", "pv", "volume", "mount", "disk latency", "iops", "inode", "filesystem", "read-only", "ceph", "storage"),
    "identity": ("401", "403", "oidc", "jwks", "issuer", "audience", "token", "certificate", "rbac", "authentication", "authorization"),
    "change": ("deploy", "deployment", "release", "rollout", "config change", "feature flag", "migration", "image digest", "jenkins"),
    "dependency": ("upstream", "downstream", "dependency", "shared dependency", "trace", "span", "circuit breaker", "fan-out"),
    "messaging": ("consumer lag", "queue depth", "dlq", "rebalance", "partition", "broker", "producer", "consumer", "kafka"),
    "recovery": ("backup", "restore", "snapshot", "rpo", "rto", "recovery point", "failover"),
}

SEVERITY_RANK = {"unknown": 0, "info": 0, "low": 1, "warning": 1, "medium": 2, "average": 2, "high": 3, "critical": 4, "disaster": 4}


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


def _evidence_id(item: Mapping[str, Any], index: int = 0) -> str:
    raw = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(raw) if raw is not None else f"anonymous:{index}"


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _flatten_text(value: Any, depth: int = 0) -> List[str]:
    if depth >= 4:
        return []
    if isinstance(value, str):
        return [value[:400]]
    if isinstance(value, Mapping):
        parts: List[str] = []
        for key, current in list(value.items())[:40]:
            normalized = str(key).lower().replace("-", "_")
            if any(token in normalized for token in ("password", "secret", "token", "authorization", "private_key", "cookie", "credential")):
                continue
            parts.extend(_flatten_text(current, depth + 1))
        return parts
    if isinstance(value, (list, tuple)):
        parts: List[str] = []
        for current in list(value)[:12]:
            parts.extend(_flatten_text(current, depth + 1))
        return parts
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    return []


def _item_text(item: Mapping[str, Any]) -> str:
    return " ".join(_flatten_text(item)).lower()


def _first_value(mapping: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, Mapping):
            for nested in ("name", "id", "hostname", "host"):
                nested_value = value.get(nested)
                if nested_value not in (None, ""):
                    return str(nested_value)
        elif value not in (None, "", "unknown"):
            return str(value)
    return None


def _signal_asset(item: Mapping[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    raw = _raw(item)
    labels = raw.get("labels") if isinstance(raw.get("labels"), Mapping) else {}
    host = _first_value(raw, ("host", "hostname", "host.name", "node", "instance", "target", "source_host"))
    if host and ":" in host and not host.startswith("http"):
        host = host.split(":", 1)[0]
    service = _first_value(raw, ("service", "service_name", "app", "application"))
    if not service and labels:
        service = _first_value(labels, ("service", "service_name", "app", "job"))
    if not host and labels:
        host = _first_value(labels, ("hostname", "host", "node", "instance", "pod"))
        if host and ":" in host:
            host = host.split(":", 1)[0]
    return host, service


def _message(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    for value in (
        item.get("message"), item.get("name"), raw.get("message"), raw.get("problem"),
        raw.get("name"), raw.get("event_name"), raw.get("reason"), raw.get("status"),
    ):
        if value not in (None, ""):
            return str(value)[:500]
    return _item_text(item)[:500]


def _severity(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    value = item.get("severity") or raw.get("severity") or raw.get("priority") or raw.get("level") or "unknown"
    return str(value).strip().lower()


def _fingerprint(signal_type: str, message: str, service: Optional[str]) -> str:
    normalized = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", message.lower())
    normalized = re.sub(r"\b\d{2,}\b", "<n>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()[:220]
    raw = f"{signal_type}|{service or ''}|{normalized}"
    return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]


def normalize_signals(raw_evidence: Iterable[Mapping[str, Any]], stale_ids: Iterable[str] = ()) -> List[Dict[str, Any]]:
    stale = {str(value) for value in stale_ids}
    normalized: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_evidence):
        if not isinstance(item, Mapping):
            continue
        evidence_id = _evidence_id(item, index)
        if evidence_id in seen_ids:
            continue
        seen_ids.add(evidence_id)
        signal_type = str(item.get("type") or "unknown").strip().lower()
        source = str(item.get("source") or "unknown").strip().lower()
        stamp = _parse_timestamp(item.get("observed_at") or item.get("timestamp") or item.get("created_at"))
        host, service = _signal_asset(item)
        message = _message(item)
        normalized.append({
            "evidence_id": evidence_id,
            "type": signal_type,
            "source": source,
            "timestamp": stamp.isoformat() if stamp else None,
            "host": host,
            "service": service,
            "message": message,
            "severity": _severity(item),
            "stale": evidence_id in stale,
            "fingerprint": _fingerprint(signal_type, message, service),
        })
    return normalized


def correlate_signals(signals: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for signal in signals:
        grouped[str(signal.get("fingerprint") or "unknown")].append(signal)
    groups: List[Dict[str, Any]] = []
    for fingerprint, rows in grouped.items():
        ids = [str(row.get("evidence_id")) for row in rows if row.get("evidence_id")]
        hosts = sorted({str(row.get("host")) for row in rows if row.get("host")})
        services = sorted({str(row.get("service")) for row in rows if row.get("service")})
        stamps = [stamp for row in rows if (stamp := _parse_timestamp(row.get("timestamp")))]
        groups.append({
            "group_id": f"corr:{fingerprint}",
            "fingerprint": fingerprint,
            "count": len(rows),
            "hosts": hosts,
            "services": services,
            "evidence_ids": ids,
            "first_seen": min(stamps).isoformat() if stamps else None,
            "last_seen": max(stamps).isoformat() if stamps else None,
            "alert_storm": len(rows) >= 3 and (len(hosts) >= 2 or len(services) >= 2),
            "individual_evidence_preserved": True,
        })
    groups.sort(key=lambda row: (row["count"], len(row["hosts"])), reverse=True)
    return groups[:24]


def _context_values(context: Mapping[str, Any]) -> Dict[str, Any]:
    summary = context.get("summary") if isinstance(context.get("summary"), Mapping) else {}
    incident = context.get("incident") if isinstance(context.get("incident"), Mapping) else {}
    merged: Dict[str, Any] = {}
    for source in (summary, incident, context):
        for key in (
            "incident_start", "started_at", "first_anomaly", "latest_change", "duration_seconds",
            "customer_impact", "customer_impacting", "affected_services", "affected_users",
            "slo_impact", "slo_burn", "error_budget_burn", "redundancy", "redundancy_status",
            "blast_radius", "environment",
        ):
            if key in source and key not in merged:
                merged[key] = source.get(key)
    return merged


def _affected_layer(asset: Mapping[str, Any]) -> str:
    asset_type = str(asset.get("asset_type") or "unknown").lower()
    platform = str(asset.get("platform") or "unknown").lower()
    if platform == "kubernetes" or "kubernetes" in asset_type:
        return "kubernetes"
    if asset_type == "database":
        return "database"
    if asset_type == "network":
        return "network"
    if asset_type == "vm" or platform == "vm" or str(asset.get("os_family") or "unknown").lower() in {"linux", "windows"}:
        return "vm"
    return "unknown"


def _domain_scores(signals: Sequence[Mapping[str, Any]], asset: Mapping[str, Any], topology: Mapping[str, Any]) -> Tuple[Dict[str, float], List[Dict[str, Any]], List[Dict[str, Any]]]:
    scores = {domain: 0.0 for domain in DOMAINS}
    reasons: Dict[str, List[str]] = defaultdict(list)
    combined = " ".join(str(signal.get("message") or "").lower() for signal in signals if not signal.get("stale"))
    for domain, keywords in DOMAIN_KEYWORDS.items():
        matched = [keyword for keyword in keywords if keyword in combined]
        if matched:
            scores[domain] += min(3.0, 0.55 * len(matched))
            reasons[domain].append("live signal matches: " + ", ".join(matched[:5]))

    affected = _affected_layer(asset)
    if affected != "unknown":
        scores[affected] += 1.35
        reasons[affected].append(f"affected asset layer is {affected}")

    causal_rules: List[Tuple[str, str, Tuple[str, ...], Tuple[str, ...], float, float, str]] = [
        ("database", "application", ("500", "5xx", "timeout", "connection pool"), ("connection exhaustion", "too many connections", "deadlock", "pg_stat", "database"), 5.0, 1.6, "application symptom with database exhaustion/latency evidence"),
        ("network", "vm", ("service down", "service failed", "systemd", "listener"), ("packet loss", "unreachable", "network path", "route", "connection timed out", "tcp"), 5.0, 1.5, "VM/service symptom with network-path evidence"),
        ("storage", "kubernetes", ("pod", "pending", "crashloop", "failedscheduling", "mount"), ("pvc", "pv", "volume", "mount", "storage"), 5.0, 1.8, "Kubernetes workload symptom with PVC/storage evidence"),
        ("infrastructure", "kubernetes", ("pod", "evict", "failedscheduling"), ("node pressure", "oom", "memory pressure", "disk pressure"), 4.2, 1.6, "Kubernetes workload symptom with node-pressure evidence"),
        ("network", "identity", ("401", "403", "authentication", "oidc"), ("dns", "nxdomain", "servfail", "jwks unreachable", "jwks timeout"), 4.5, 2.0, "authentication symptom with DNS/JWKS reachability evidence"),
        ("storage", "database", ("database", "query", "wal", "checkpoint"), ("disk latency", "iowait", "iops", "filesystem", "storage"), 4.6, 1.7, "database latency/failure with storage-pressure evidence"),
    ]
    causal_matches: List[Dict[str, Any]] = []
    for primary, secondary, symptom_tokens, cause_tokens, primary_weight, secondary_weight, description in causal_rules:
        symptom_hits = [token for token in symptom_tokens if token in combined]
        cause_hits = [token for token in cause_tokens if token in combined]
        if symptom_hits and cause_hits:
            scores[primary] += primary_weight
            scores[secondary] += secondary_weight
            reasons[primary].append(description)
            reasons[secondary].append(f"observed symptom layer; probable cause routes to {primary}")
            causal_matches.append({
                "primary_domain": primary,
                "symptom_domain": secondary,
                "reason": description,
                "symptom_matches": symptom_hits[:4],
                "cause_matches": cause_hits[:4],
            })

    edges = topology.get("edges") if isinstance(topology.get("edges"), list) else topology.get("topology_edges")
    if isinstance(edges, list) and edges:
        scores["dependency"] += min(2.0, 0.35 * len(edges))
        reasons["dependency"].append("live topology/dependency edges are available")

    route_reasons = [
        {"route": domain, "score": round(score, 3), "reasons": reasons.get(domain, [])}
        for domain, score in sorted(scores.items(), key=lambda row: row[1], reverse=True)
        if score > 0
    ]
    return scores, route_reasons, causal_matches


def _domain_coverage(signals: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    available_types = Counter(str(signal.get("type") or "unknown").lower() for signal in signals if not signal.get("stale"))
    coverage: Dict[str, Dict[str, Any]] = {}
    for domain, required in DOMAIN_REQUIREMENTS.items():
        have = [kind for kind in required if available_types.get(kind, 0) > 0]
        missing = [kind for kind in required if kind not in have]
        score = len(have) / len(required) if required else 1.0
        coverage[domain] = {
            "required": list(required),
            "have": have,
            "missing": missing,
            "coverage": round(score, 4),
            "counts": {kind: available_types.get(kind, 0) for kind in required},
        }
    return coverage


def _timeline(signals: Sequence[Mapping[str, Any]], context: Mapping[str, Any]) -> Dict[str, Any]:
    fresh = [signal for signal in signals if not signal.get("stale")]
    ordered = sorted(
        [signal for signal in fresh if signal.get("timestamp")],
        key=lambda row: str(row.get("timestamp")),
    )
    values = _context_values(context)
    incident_start = _parse_timestamp(values.get("incident_start") or values.get("started_at"))
    first_anomaly = _parse_timestamp(values.get("first_anomaly"))
    if first_anomaly is None and ordered:
        first_anomaly = _parse_timestamp(ordered[0].get("timestamp"))
    latest_change = _parse_timestamp(values.get("latest_change"))
    if latest_change is None:
        change_rows = [
            signal for signal in ordered
            if any(token in str(signal.get("message") or "").lower() for token in DOMAIN_KEYWORDS["change"])
        ]
        if change_rows:
            latest_change = _parse_timestamp(change_rows[-1].get("timestamp"))
    propagation = [
        {
            "timestamp": signal.get("timestamp"),
            "evidence_id": signal.get("evidence_id"),
            "type": signal.get("type"),
            "host": signal.get("host"),
            "service": signal.get("service"),
            "message": str(signal.get("message") or "")[:180],
        }
        for signal in ordered[:20]
    ]
    return {
        "incident_start": incident_start.isoformat() if incident_start else None,
        "first_anomaly": first_anomaly.isoformat() if first_anomaly else None,
        "latest_change": latest_change.isoformat() if latest_change else None,
        "propagation_order": propagation,
    }


def _impact_severity(signals: Sequence[Mapping[str, Any]], context: Mapping[str, Any], groups: Sequence[Mapping[str, Any]]) -> Tuple[str, str, Dict[str, Any]]:
    values = _context_values(context)
    text = " ".join(str(signal.get("message") or "").lower() for signal in signals if not signal.get("stale"))
    customer_raw = values.get("customer_impacting", values.get("customer_impact"))
    customer_impact = customer_raw is True or str(customer_raw).strip().lower() in {"true", "yes", "impacting", "affected", "major"}
    customer_impact_absent = customer_raw is False or str(customer_raw).strip().lower() in {"false", "no", "none", "unaffected"}
    affected_services_raw = values.get("affected_services")
    if isinstance(affected_services_raw, (list, tuple, set)):
        affected_services = len(affected_services_raw)
    else:
        try:
            affected_services = int(affected_services_raw or 0)
        except (TypeError, ValueError):
            affected_services = 0
    observed_services = {str(signal.get("service")) for signal in signals if signal.get("service") and not signal.get("stale")}
    affected_services = max(affected_services, len(observed_services))
    try:
        duration_seconds = float(values.get("duration_seconds") or 0)
    except (TypeError, ValueError):
        duration_seconds = 0.0
    slo_value = values.get("slo_impact", values.get("slo_burn", values.get("error_budget_burn")))
    slo_impact = bool(slo_value) and str(slo_value).strip().lower() not in {"0", "0.0", "false", "none", "no"}
    redundancy = str(values.get("redundancy_status") or values.get("redundancy") or "unknown").strip().lower()
    redundancy_healthy = redundancy in {"healthy", "available", "redundant", "n+1", "active-active"}
    redundancy_lost = redundancy in {"none", "lost", "degraded", "single", "no_redundancy"}
    label_rank = max((SEVERITY_RANK.get(str(signal.get("severity") or "unknown").lower(), 0) for signal in signals if not signal.get("stale")), default=0)
    host_count = len({str(signal.get("host")) for signal in signals if signal.get("host") and not signal.get("stale")})
    storm_groups = sum(1 for group in groups if group.get("alert_storm"))

    score = 0
    reasons: List[str] = []
    if customer_impact:
        score += 2
        reasons.append("customer impact is evidenced")
    if affected_services >= 3:
        score += 2
        reasons.append(f"{affected_services} services are affected")
    elif affected_services == 2:
        score += 1
        reasons.append("multiple services are affected")
    if host_count >= 4:
        score += 1
        reasons.append(f"symptoms span {host_count} hosts")
    if duration_seconds >= 1800:
        score += 2
        reasons.append("incident duration exceeds 30 minutes")
    elif duration_seconds >= 600:
        score += 1
        reasons.append("incident duration exceeds 10 minutes")
    if slo_impact:
        score += 2
        reasons.append("SLO/error-budget impact is present")
    if redundancy_lost:
        score += 1
        reasons.append("redundancy is degraded or absent")
    if redundancy_healthy:
        score -= 1
        reasons.append("healthy redundancy reduces urgency")
    if label_rank >= 4:
        score += 1
        reasons.append("critical source label contributes only one bounded severity point")
    if customer_impact_absent:
        score -= 1
        reasons.append("no customer impact is currently evidenced")

    if score >= 6:
        severity = "critical"
    elif score >= 3:
        severity = "high"
    elif score >= 1:
        severity = "medium"
    else:
        severity = "low"
    if customer_impact_absent and redundancy_healthy and severity in {"high", "critical"}:
        severity = "medium"
        reasons.append("severity capped because customer impact is absent and redundancy remains healthy")
    if not reasons:
        reasons.append("impact evidence is insufficient; alert labels are not treated as severity proof")
    return severity, "; ".join(reasons[:5]), {
        "score": score,
        "customer_impact": customer_impact,
        "customer_impact_explicitly_absent": customer_impact_absent,
        "affected_services": affected_services,
        "affected_hosts": host_count,
        "duration_seconds": duration_seconds,
        "slo_impact": slo_impact,
        "redundancy": redundancy,
        "max_alert_label_rank": label_rank,
        "alert_storm_groups": storm_groups,
    }


def build_triage_decision_support(
    *,
    fresh_evidence: Iterable[Mapping[str, Any]],
    raw_evidence: Iterable[Mapping[str, Any]],
    stale_ids: Iterable[str],
    asset: Mapping[str, Any],
    topology: Mapping[str, Any],
    context: Mapping[str, Any],
    enabled_domains: Iterable[str],
    max_routes: int,
) -> Dict[str, Any]:
    enabled = [domain for domain in DOMAINS if domain in {str(value).lower() for value in enabled_domains}]
    stale_set = {str(value) for value in stale_ids}
    normalized = normalize_signals(raw_evidence, stale_set)
    fresh_ids = {_evidence_id(item, index) for index, item in enumerate(fresh_evidence) if isinstance(item, Mapping)}
    for signal in normalized:
        if signal["evidence_id"] not in fresh_ids:
            signal["stale"] = signal["stale"] or signal["evidence_id"] in stale_set
    groups = correlate_signals(normalized)
    scores, route_reasons, causal_matches = _domain_scores(normalized, asset, topology)
    coverage = _domain_coverage(normalized)
    timeline = _timeline(normalized, context)
    conflicts = list(asset.get("topology_conflicts") or [])
    if isinstance(topology.get("conflicts"), list):
        for conflict in topology.get("conflicts") or []:
            if conflict not in conflicts:
                conflicts.append(conflict)

    ranked = [(domain, scores.get(domain, 0.0)) for domain in enabled]
    ranked.sort(key=lambda row: row[1], reverse=True)
    top_domain, top_score = ranked[0] if ranked else ("unknown", 0.0)
    second_score = ranked[1][1] if len(ranked) > 1 else 0.0
    affected_layer = _affected_layer(asset)
    asset_confidence = float(asset.get("confidence", 0) or 0)
    unknown_asset = asset_confidence < 0.5 and affected_layer == "unknown" and not asset.get("knowledge_assisted")

    if top_score <= 0:
        primary = "unknown"
        deterministic_confidence = 0.0
    else:
        primary = top_domain
        separation = max(0.0, top_score - second_score)
        deterministic_confidence = min(0.96, 0.42 + min(top_score, 7.0) * 0.055 + min(separation, 4.0) * 0.06)
    if conflicts:
        deterministic_confidence *= max(0.35, 1.0 - min(3, len(conflicts)) * 0.18)
    if unknown_asset:
        deterministic_confidence = min(deterministic_confidence, 0.45)
    if normalized and all(signal.get("stale") for signal in normalized):
        deterministic_confidence = min(deterministic_confidence, 0.25)
    deterministic_confidence = round(max(0.0, min(1.0, deterministic_confidence)), 4)

    if deterministic_confidence >= 0.75 and not conflicts:
        band = "high"
    elif deterministic_confidence >= 0.5 and not conflicts:
        band = "medium"
    else:
        band = "low"

    secondary_candidates: List[str] = []
    for match in causal_matches:
        symptom_domain = str(match["symptom_domain"])
        if symptom_domain in enabled and symptom_domain != primary and symptom_domain not in secondary_candidates:
            secondary_candidates.append(symptom_domain)
    for domain, score in ranked[1:]:
        if score <= 0 or domain == primary or domain in secondary_candidates:
            continue
        if score >= max(1.0, top_score * 0.45):
            secondary_candidates.append(domain)

    if band == "high":
        route_budget = min(max_routes, 2)
    elif band == "medium":
        route_budget = min(max_routes, 3)
    else:
        route_budget = max_routes
    routes: List[str] = []
    for candidate in ([primary] if primary != "unknown" else []) + secondary_candidates + [domain for domain, score in ranked if score > 0]:
        if candidate in enabled and candidate not in routes:
            routes.append(candidate)
        if len(routes) >= route_budget:
            break
    if band == "low" and len(routes) < route_budget:
        for domain in enabled:
            if domain not in routes:
                routes.append(domain)
            if len(routes) >= route_budget:
                break

    rejected = []
    selected_set = set(routes)
    reason_lookup = {row["route"]: row for row in route_reasons}
    for domain in enabled:
        if domain in selected_set:
            continue
        score = round(scores.get(domain, 0.0), 3)
        rejected.append({
            "route": domain,
            "score": score,
            "reason": "lower deterministic evidence score within routing budget" if score > 0 else "no direct live/topology signal for domain",
        })

    primary_coverage = coverage.get(primary, {"coverage": 0.0, "have": [], "missing": []})
    evidence_gaps: List[Dict[str, Any]] = []
    focus_domains = routes[: max(1, min(3, len(routes)))] or ([primary] if primary != "unknown" else [])
    for domain in focus_domains:
        row = coverage.get(domain, {"have": [], "missing": [], "coverage": 0.0})
        evidence_gaps.append({
            "domain": domain,
            "have": list(row.get("have") or []),
            "missing": list(row.get("missing") or []),
            "coverage": row.get("coverage", 0.0),
        })
    if unknown_asset:
        evidence_gaps.append({"domain": "asset_identity", "have": [], "missing": ["live asset identity metadata"], "coverage": 0.0})
    if conflicts:
        evidence_gaps.append({"domain": "topology", "have": ["conflicting topology observations"], "missing": ["live conflict resolution"], "coverage": 0.0})
    if stale_set:
        evidence_gaps.append({"domain": "freshness", "have": [f"{len(stale_set)} stale evidence references"], "missing": ["fresh replacement observations"], "coverage": 0.0})

    next_best: List[Dict[str, Any]] = []
    information_gain = 1.0
    for gap in evidence_gaps:
        for missing in gap.get("missing") or []:
            item = {
                "domain": gap.get("domain"),
                "evidence": missing,
                "information_gain": round(information_gain, 2),
                "reason": "closes a routing/causality uncertainty gap",
            }
            if item not in next_best:
                next_best.append(item)
            information_gain = max(0.45, information_gain - 0.08)
    next_best = next_best[:8]

    severity, urgency_reason, severity_details = _impact_severity(normalized, context, groups)
    services = sorted({str(signal.get("service")) for signal in normalized if signal.get("service") and not signal.get("stale")})
    hosts = sorted({str(signal.get("host")) for signal in normalized if signal.get("host") and not signal.get("stale")})
    if len(services) >= 3 or len(hosts) >= 5:
        blast_radius = f"multi-service/multi-host: services={len(services)}, hosts={len(hosts)}"
    elif len(services) >= 2 or len(hosts) >= 2:
        blast_radius = f"bounded multi-target: services={len(services)}, hosts={len(hosts)}"
    elif services or hosts:
        blast_radius = "single-service-or-host"
    else:
        blast_radius = str(_context_values(context).get("blast_radius") or "unknown")

    stale_rows = [signal for signal in normalized if signal.get("stale")]
    fresh_rows = [signal for signal in normalized if not signal.get("stale")]
    storm_groups = [group for group in groups if group.get("alert_storm")]
    selected_reasons = [reason_lookup.get(route, {"route": route, "score": scores.get(route, 0.0), "reasons": []}) for route in routes]

    return {
        "policy": "deterministic routing and impact guardrails; LLM may resolve residual ambiguity but cannot override stronger live causal evidence",
        "normalized_signals": normalized[:40],
        "correlation_groups": groups,
        "alert_storm_groups": storm_groups,
        "timeline": timeline,
        "affected_layer": affected_layer,
        "probable_causal_layer": primary,
        "primary_domain": primary,
        "secondary_domains": secondary_candidates[:5],
        "domain_scores": {domain: round(score, 3) for domain, score in ranked},
        "domain_evidence_coverage": coverage,
        "evidence_gap_matrix": evidence_gaps,
        "next_best_evidence": next_best,
        "specialist_routes": routes,
        "route_reasons": selected_reasons,
        "rejected_routes": rejected,
        "causal_matches": causal_matches,
        "routing_confidence": deterministic_confidence,
        "routing_confidence_band": band,
        "blast_radius": blast_radius,
        "severity": severity,
        "urgency_reason": urgency_reason,
        "severity_details": severity_details,
        "topology_conflicts": conflicts,
        "unknown_asset": unknown_asset,
        "stale_evidence_ids": [str(row.get("evidence_id")) for row in stale_rows],
        "fresh_evidence_count": len(fresh_rows),
        "stale_evidence_count": len(stale_rows),
        "primary_domain_coverage": primary_coverage.get("coverage", 0.0),
        "alert_storm_not_incident_storm": bool(storm_groups),
        "individual_evidence_preserved": all(bool(group.get("individual_evidence_preserved")) for group in groups),
    }
