from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


_SENSITIVE_KEYS = {
    "authorization", "password", "passwd", "secret", "private_key", "access_token",
    "refresh_token", "id_token", "client_secret", "api_key", "credential", "cookie",
    "set-cookie", "token_value", "secret_value",
}

_AUTH_FAIL = ("failed login", "login failed", "authentication failed", "invalid password", "invalid credentials", "unauthorized", "401")
_AUTHZ_DENY = ("forbidden", "authorization denied", "access denied", "permission denied", "rbac", "403", "policy deny")
_PROCESS = ("process exec", "process execution", "execve", "spawned process", "unexpected binary", "suspicious process", "process tree")
_PRIVILEGE = ("privilege escalation", "setuid", "sudo", "runas", "impersonat", "cluster-admin", "root shell", "cap_sys_admin")
_OUTBOUND = ("unexpected outbound", "egress", "outbound connection", "connect()", "destination_ip", "destination port")
_SCAN = ("port scan", "scan-like", "connection attempts", "many destinations", "many ports", "syn scan", "reconnaissance")
_RUNTIME = ("container runtime", "runtime security", "falco", "seccomp", "apparmor", "container escape", "exec in container")
_POLICY = ("policy violation", "policy deny", "denied by policy", "admission denied", "blocked by policy")
_FILE = ("unexpected file access", "sensitive path", "/etc/shadow", "/proc/", "file access denied", "path access")
_TOKEN = ("token", "jwt", "bearer", "service account", "serviceaccount")
_EXPIRED = ("token expired", "expired token", "jwt expired", "exp claim", "signature has expired")
_RBAC_MISCONFIG = ("rbac misconfig", "misconfigured rbac", "missing rolebinding", "role binding missing", "forbidden by rbac")

_ATTACK_STAGE_MAP = {
    "credential_access": ("credential theft", "token theft", "secret access", "credential dump"),
    "execution": ("malicious process", "unexpected binary", "execve", "command execution"),
    "privilege_escalation": _PRIVILEGE,
    "discovery": _SCAN,
    "command_and_control": ("beacon", "c2", "command and control", "unexpected outbound"),
    "exfiltration": ("exfiltration", "data transfer to external", "bulk outbound transfer"),
    "defense_evasion": ("disable security", "tamper", "clear logs", "delete audit"),
}


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


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _eid(item: Mapping[str, Any], index: int) -> str:
    for key in ("evidence_id", "id", "reference", "source_id"):
        if item.get(key) not in (None, ""):
            return str(item[key])
    return f"anonymous:{index}"


def _timestamp(item: Mapping[str, Any]) -> Optional[datetime]:
    raw = _raw(item)
    for value in (item.get("observed_at"), item.get("timestamp"), item.get("created_at"), raw.get("timestamp"), raw.get("@timestamp")):
        parsed = _parse_time(value)
        if parsed:
            return parsed
    return None


def _safe_text(value: Any, depth: int = 0) -> str:
    if depth > 4:
        return ""
    if isinstance(value, str):
        text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        return text[:900]
    if isinstance(value, Mapping):
        parts: List[str] = []
        for key, current in list(value.items())[:100]:
            normalized = str(key).lower().replace("-", "_")
            if normalized in _SENSITIVE_KEYS or any(token in normalized for token in ("password", "private_key", "client_secret", "access_token", "refresh_token")):
                continue
            part = _safe_text(current, depth + 1)
            if part:
                parts.append(part)
        return " ".join(parts)
    if isinstance(value, (list, tuple)):
        return " ".join(_safe_text(current, depth + 1) for current in list(value)[:40])
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def _text(item: Mapping[str, Any]) -> str:
    return _safe_text(item).lower()


def _first(item: Mapping[str, Any], *keys: str) -> Optional[str]:
    raw = _raw(item)
    for key in keys:
        for source in (item, raw):
            value = source.get(key)
            if value not in (None, "") and not isinstance(value, (Mapping, list, tuple)):
                return str(value)[:180]
    return None


def _identity(item: Mapping[str, Any]) -> Optional[str]:
    return _first(item, "user", "username", "principal", "identity", "service_account", "serviceAccount", "subject")


def _asset(item: Mapping[str, Any]) -> Optional[str]:
    return _first(item, "host", "hostname", "node", "pod", "asset", "instance", "device")


def _service(item: Mapping[str, Any]) -> Optional[str]:
    return _first(item, "service", "service_name", "application", "app", "workload")


def _source_ip(item: Mapping[str, Any]) -> Optional[str]:
    return _first(item, "source_ip", "src_ip", "client_ip", "remote_ip", "source.address")


def _destination_ip(item: Mapping[str, Any]) -> Optional[str]:
    return _first(item, "destination_ip", "dst_ip", "remote_address", "destination.address")


def _port(item: Mapping[str, Any]) -> Optional[str]:
    return _first(item, "destination_port", "dst_port", "port", "listener_port", "local_port")


def _is_public_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _normalize(items: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            continue
        stamp = _timestamp(item)
        text = _text(item)
        result.append({
            "evidence_id": _eid(item, index),
            "type": str(item.get("type") or "unknown").lower(),
            "source": str(item.get("source") or "unknown").lower(),
            "timestamp": stamp.isoformat() if stamp else None,
            "identity": _identity(item),
            "asset": _asset(item),
            "service": _service(item),
            "source_ip": _source_ip(item),
            "destination_ip": _destination_ip(item),
            "port": _port(item),
            "text": text[:1200],
        })
    return result


def _event(code: str, category: str, severity: str, row: Mapping[str, Any], *, details: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    return {
        "code": code,
        "category": category,
        "severity": severity,
        "evidence_ids": [str(row.get("evidence_id"))],
        "timestamp": row.get("timestamp"),
        "identity": row.get("identity"),
        "asset": row.get("asset"),
        "service": row.get("service"),
        "source_ip": row.get("source_ip"),
        "destination_ip": row.get("destination_ip"),
        "port": row.get("port"),
        "details": dict(details or {}),
    }


def _signal_events(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for row in rows:
        text = str(row.get("text") or "")
        if any(token in text for token in _AUTH_FAIL):
            events.append(_event("authentication_failure", "authentication", "medium", row))
        if any(token in text for token in _AUTHZ_DENY):
            events.append(_event("authorization_denied", "authorization", "medium", row))
        if any(token in text for token in _PROCESS):
            events.append(_event("suspicious_process_execution", "process", "high", row))
        if any(token in text for token in _PRIVILEGE):
            events.append(_event("privilege_escalation_indicator", "privilege", "high", row))
        if any(token in text for token in _OUTBOUND) or (_is_public_ip(row.get("destination_ip")) and row.get("type") in {"log", "event", "telemetry"}):
            events.append(_event("unexpected_outbound_connection", "network", "medium", row, details={"public_destination": _is_public_ip(row.get("destination_ip"))}))
        if any(token in text for token in _SCAN):
            events.append(_event("scan_like_activity", "network", "high", row))
        if any(token in text for token in _RUNTIME):
            events.append(_event("runtime_security_event", "runtime", "high", row))
        if any(token in text for token in _POLICY):
            events.append(_event("policy_violation_or_deny", "policy", "medium", row))
        if any(token in text for token in _FILE):
            events.append(_event("unusual_file_path_access", "file", "medium", row))
        if any(token in text for token in _TOKEN):
            events.append(_event("token_or_service_account_metadata_event", "identity", "low", row))
        if row.get("port") and any(token in text for token in ("listener", "listening", "unexpected port", "open port")):
            events.append(_event("unusual_port_or_listener", "network", "medium", row))
    return events


def _trend(events: Sequence[Mapping[str, Any]], code: str) -> Dict[str, Any]:
    selected = [row for row in events if row.get("code") == code]
    stamps = [_parse_time(row.get("timestamp")) for row in selected]
    stamps = [stamp for stamp in stamps if stamp]
    identities = sorted({str(row.get("identity")) for row in selected if row.get("identity")})
    sources = sorted({str(row.get("source_ip")) for row in selected if row.get("source_ip")})
    return {
        "count": len(selected),
        "first_seen": min(stamps).isoformat() if stamps else None,
        "last_seen": max(stamps).isoformat() if stamps else None,
        "identity_count": len(identities),
        "source_count": len(sources),
        "identities": identities[:12],
        "sources": sources[:12],
        "evidence_ids": list(dict.fromkeys(str(row.get("evidence_ids", [""])[0]) for row in selected))[:30],
    }


def _network_aggregation(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    destinations: Dict[str, Set[str]] = defaultdict(set)
    ports: Dict[str, Set[str]] = defaultdict(set)
    evidence_by_source: Dict[str, List[str]] = defaultdict(list)
    for row in rows:
        source = str(row.get("source_ip") or row.get("asset") or "unknown")
        if row.get("destination_ip"):
            destinations[source].add(str(row["destination_ip"]))
        if row.get("port"):
            ports[source].add(str(row["port"]))
        if row.get("destination_ip") or row.get("port"):
            evidence_by_source[source].append(str(row.get("evidence_id")))
    scan_candidates = []
    for source in sorted(set(destinations) | set(ports)):
        dest_count = len(destinations.get(source, set()))
        port_count = len(ports.get(source, set()))
        if dest_count >= 8 or port_count >= 10:
            scan_candidates.append({
                "source": source,
                "unique_destination_count": dest_count,
                "unique_port_count": port_count,
                "evidence_ids": list(dict.fromkeys(evidence_by_source[source]))[:30],
            })
    return {
        "scan_candidates": scan_candidates[:10],
        "unique_public_destinations": sorted({str(row.get("destination_ip")) for row in rows if _is_public_ip(row.get("destination_ip"))})[:30],
    }


def _false_positive_analysis(rows: Sequence[Mapping[str, Any]], events: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    expired = [row for row in rows if any(token in str(row.get("text") or "") for token in _EXPIRED)]
    if expired:
        result.append({
            "explanation": "expired or time-invalid token can produce repeated authentication failures without credential compromise",
            "evidence_ids": [str(row.get("evidence_id")) for row in expired[:20]],
            "verification": "compare token exp/nbf, clock skew, issuer/audience and successful authentication from the same identity",
        })
    rbac = [row for row in rows if any(token in str(row.get("text") or "") for token in _RBAC_MISCONFIG)]
    if rbac:
        result.append({
            "explanation": "RBAC/configuration drift can generate authorization denies without malicious activity",
            "evidence_ids": [str(row.get("evidence_id")) for row in rbac[:20]],
            "verification": "compare effective roles/bindings and recent access-policy changes",
        })
    noisy = Counter(str(row.get("text") or "")[:180] for row in rows if row.get("type") == "log")
    repeated = [text for text, count in noisy.items() if text and count >= 5]
    if repeated:
        ids = [str(row.get("evidence_id")) for row in rows if str(row.get("text") or "")[:180] in repeated][:20]
        result.append({
            "explanation": "high-volume duplicate logs can be instrumentation noise or retry amplification rather than independent malicious events",
            "evidence_ids": ids,
            "verification": "deduplicate by request/session/source and compare unique actors and successful outcomes",
        })
    if not result and events:
        result.append({
            "explanation": "benign administrative, deployment, scanner or automation activity remains possible until actor/change context is verified",
            "evidence_ids": [],
            "verification": "correlate actor, approved change window, asset owner and expected automation identity",
        })
    return result[:6]


def _timeline(rows: Sequence[Mapping[str, Any]], events: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    event_codes_by_id: Dict[str, List[str]] = defaultdict(list)
    for event in events:
        for eid in event.get("evidence_ids") or []:
            event_codes_by_id[str(eid)].append(str(event.get("code")))
    result = []
    for row in rows:
        if not row.get("timestamp"):
            continue
        result.append({
            "timestamp": row.get("timestamp"),
            "evidence_id": row.get("evidence_id"),
            "type": row.get("type"),
            "source": row.get("source"),
            "identity": row.get("identity"),
            "asset": row.get("asset"),
            "service": row.get("service"),
            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "signals": event_codes_by_id.get(str(row.get("evidence_id")), []),
        })
    result.sort(key=lambda row: str(row.get("timestamp")))
    return result[:120]


def _blast_radius(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    identities = sorted({str(row.get("identity")) for row in rows if row.get("identity")})
    assets = sorted({str(row.get("asset")) for row in rows if row.get("asset")})
    services = sorted({str(row.get("service")) for row in rows if row.get("service")})
    public_destinations = sorted({str(row.get("destination_ip")) for row in rows if _is_public_ip(row.get("destination_ip"))})
    score = len(identities) + len(assets) + len(services)
    if score == 0:
        scope = "unknown"
    elif score <= 2:
        scope = "localized"
    elif score <= 6:
        scope = "multi-asset"
    else:
        scope = "broad"
    return {
        "scope": scope,
        "identities": identities[:30],
        "assets": assets[:30],
        "services": services[:30],
        "public_destinations": public_destinations[:30],
        "identity_count": len(identities),
        "asset_count": len(assets),
        "service_count": len(services),
    }


def _direct_confirmation_score(rows: Sequence[Mapping[str, Any]]) -> Tuple[int, List[str], Set[str]]:
    evidence_ids: List[str] = []
    sources: Set[str] = set()
    for row in rows:
        text = str(row.get("text") or "")
        high_specificity = any(token in text for token in (
            "malware hash match", "edr verdict malicious", "credential theft confirmed",
            "exfiltration confirmed", "compromise confirmed by", "forensic artifact confirmed",
        ))
        if high_specificity:
            evidence_ids.append(str(row.get("evidence_id")))
            sources.add(str(row.get("source")))
    return len(set(evidence_ids)), list(dict.fromkeys(evidence_ids)), sources


def _classification(rows: Sequence[Mapping[str, Any]], events: Sequence[Mapping[str, Any]], network: Mapping[str, Any]) -> Dict[str, Any]:
    categories = {str(event.get("category")) for event in events}
    direct_count, direct_ids, direct_sources = _direct_confirmation_score(rows)
    suspicious_high = sum(1 for event in events if event.get("severity") == "high" and event.get("category") not in {"policy", "authorization"})
    policy_count = sum(1 for event in events if event.get("category") in {"policy", "authorization"})
    corroborated_attack = len(categories & {"process", "privilege", "network", "runtime", "file", "identity"}) >= 2
    corroborated_attack = corroborated_attack or bool(network.get("scan_candidates"))

    if direct_count >= 2 and len(direct_sources) >= 2:
        level = "confirmed_compromise"
        confidence_cap = 0.98
        reason = "multiple independent high-specificity live security artifacts corroborate compromise"
    elif corroborated_attack and suspicious_high >= 2:
        level = "probable_attack"
        confidence_cap = 0.85
        reason = "multiple live security signal categories corroborate an attack hypothesis"
    elif policy_count and suspicious_high == 0:
        level = "policy_violation"
        confidence_cap = 0.65
        reason = "policy/authorization evidence exists without independent malicious-behavior corroboration"
    elif events:
        level = "observed_suspicious_event"
        confidence_cap = 0.55
        reason = "security-relevant event observed but evidence is insufficient for attack or compromise conclusion"
    else:
        level = "insufficient_evidence"
        confidence_cap = 0.35
        reason = "no sufficiently specific live security signal"
    return {
        "level": level,
        "confidence_cap": confidence_cap,
        "reason": reason,
        "direct_confirmation_evidence_ids": direct_ids,
        "direct_confirmation_source_count": len(direct_sources),
        "single_alert_can_confirm_compromise": False,
    }


def _mitre_mapping(rows: Sequence[Mapping[str, Any]], classification: Mapping[str, Any]) -> Dict[str, Any]:
    matches: List[Dict[str, Any]] = []
    combined = " ".join(str(row.get("text") or "") for row in rows)
    for stage, tokens in _ATTACK_STAGE_MAP.items():
        ids = [str(row.get("evidence_id")) for row in rows if any(token in str(row.get("text") or "") for token in tokens)]
        if ids:
            matches.append({"stage": stage, "evidence_ids": list(dict.fromkeys(ids))[:20]})
    if classification.get("level") in {"probable_attack", "confirmed_compromise"}:
        return {"status": "evidence_supported_mapping", "stages": matches[:8]}
    return {"status": "hypothesis_only", "stages": matches[:8], "reason": "attack-stage mapping requires corroborated live evidence"}


def _next_best_evidence(classification: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    categories = {str(event.get("category")) for event in events}
    result: List[Dict[str, Any]] = []
    def add(evidence: str, reason: str, source: str, gain: float) -> None:
        result.append({"evidence": evidence, "reason": reason, "preferred_source": source, "information_gain": gain})
    if "authentication" in categories or "authorization" in categories or "identity" in categories:
        add("identity-provider audit trail with actor, result, issuer/audience and policy decision metadata", "separate expired/misconfigured credentials from misuse", "identity", 0.95)
    if "process" in categories or "privilege" in categories:
        add("process tree with parent/child hashes, signer/package provenance and execution user", "verify whether process execution is expected software or malicious", "host/runtime telemetry", 0.94)
    if "network" in categories:
        add("flow logs and listener/process ownership for source-destination-port tuple", "distinguish expected service traffic, scanning and command/control hypotheses", "network", 0.92)
    if "runtime" in categories:
        add("container runtime/audit event with pod image digest, actor and syscall/process context", "validate runtime-security alert specificity", "runtime", 0.90)
    if classification.get("level") == "insufficient_evidence":
        add("authentication/authorization audit logs", "establish whether a security-relevant event occurred", "identity/elasticsearch", 0.90)
        add("host/process and network telemetry", "look for independent execution or network corroboration", "telemetry", 0.85)
    add("approved change/automation context for affected identities and assets", "test benign automation or configuration explanations", "change", 0.65)
    seen: Set[str] = set()
    deduped = []
    for row in sorted(result, key=lambda value: float(value["information_gain"]), reverse=True):
        if row["evidence"] in seen:
            continue
        seen.add(row["evidence"])
        deduped.append(row)
    return deduped[:8]


def _deterministic_hypotheses(rows: Sequence[Mapping[str, Any]], events: Sequence[Mapping[str, Any]], classification: Mapping[str, Any], false_positives: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    by_code: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        by_code[str(event.get("code"))].append(event)
    alternatives = [str(row.get("explanation")) for row in false_positives if row.get("explanation")]
    result: List[Dict[str, Any]] = []

    def add(name: str, codes: Sequence[str], verification: str, confidence: float) -> None:
        matched = [event for code in codes for event in by_code.get(code, [])]
        if not matched:
            return
        ids = list(dict.fromkeys(str(eid) for event in matched for eid in event.get("evidence_ids") or []))
        identities = sorted({str(event.get("identity")) for event in matched if event.get("identity")})
        assets = sorted({str(event.get("asset")) for event in matched if event.get("asset")})
        result.append({
            "hypothesis": name,
            "supporting_evidence_ids": ids[:20],
            "conflicting_evidence_ids": [],
            "alternative_benign_explanations": alternatives[:3] or ["expected administrative or automation activity remains possible"],
            "required_verification": verification,
            "affected_identities": identities[:20],
            "affected_assets": assets[:20],
            "confidence": min(confidence, float(classification.get("confidence_cap") or 0.35)),
        })

    add("credential misuse or brute-force style activity", ["authentication_failure"], "compare unique sources, successful logins, MFA/session events and identity-provider audit trail", 0.55)
    add("unauthorized privilege or execution activity", ["suspicious_process_execution", "privilege_escalation_indicator"], "validate process ancestry, hashes/signatures, execution user and approved change context", 0.72)
    add("network reconnaissance or unexpected outbound activity", ["scan_like_activity", "unexpected_outbound_connection", "unusual_port_or_listener"], "validate flow logs, owning process, destination reputation/context and expected service topology", 0.68)
    add("runtime/container security violation", ["runtime_security_event"], "validate image digest, runtime/audit event, process/syscall context and workload owner", 0.68)
    return result[:6]


def _peer_context(context: Mapping[str, Any], live_ids: Set[str]) -> Dict[str, Any]:
    summary = context.get("summary") if isinstance(context, Mapping) else None
    peer = summary.get("peer_operational_context") if isinstance(summary, Mapping) else None
    if not isinstance(peer, Mapping):
        peer = {"findings": context.get("peer_findings") if isinstance(context.get("peer_findings"), list) else []}
    findings = []
    handoffs = []
    for raw in list(peer.get("findings") or [])[:20]:
        if not isinstance(raw, Mapping):
            continue
        agent = str(raw.get("agent_name") or "unknown").lower()
        if agent not in {"identity", "network", "application"}:
            continue
        cited = [str(value) for value in raw.get("evidence_ids") or [] if value]
        linked = [value for value in cited if value in live_ids]
        findings.append({
            "agent_name": agent,
            "statement": str(raw.get("statement") or "")[:520],
            "cited_evidence_ids": cited[:20],
            "live_linked_evidence_ids": linked[:20],
            "validation_status": "live_evidence_linked" if linked else "unverified_peer_analysis",
        })
        if linked and agent not in handoffs:
            handoffs.append(agent)
    return {
        "policy": "peer_output_is_auxiliary_only; do_not_inherit_peer_confidence; live_evidence_link_validates_reference_not_peer_causal_claim",
        "findings": findings,
        "linked_handoff_candidates": handoffs,
    }


def build_security_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    rows = _normalize(items)
    events = _signal_events(rows)
    network = _network_aggregation(rows)
    for candidate in network.get("scan_candidates") or []:
        if not any(event.get("code") == "scan_like_activity" and set(event.get("evidence_ids") or []) & set(candidate.get("evidence_ids") or []) for event in events):
            events.append({
                "code": "scan_like_activity", "category": "network", "severity": "high",
                "evidence_ids": candidate.get("evidence_ids") or [], "timestamp": None,
                "identity": None, "asset": candidate.get("source"), "service": service_name,
                "source_ip": candidate.get("source"), "destination_ip": None, "port": None,
                "details": {"unique_destination_count": candidate.get("unique_destination_count"), "unique_port_count": candidate.get("unique_port_count")},
            })
    classification = _classification(rows, events, network)
    false_positives = _false_positive_analysis(rows, events)
    blast = _blast_radius(rows)
    live_ids = {str(row.get("evidence_id")) for row in rows}
    peer = _peer_context(context or {}, live_ids)
    handoffs = list(peer.get("linked_handoff_candidates") or [])
    categories = {str(event.get("category")) for event in events}
    for target, relevant in (("identity", {"authentication", "authorization", "identity", "privilege"}), ("network", {"network"}), ("application", {"authentication", "authorization"})):
        if categories & relevant and target not in handoffs:
            handoffs.append(target)
    return {
        "policy": "live_evidence_only_for_security_conclusions; single_alert_never_confirms_compromise; containment_is_recommendation_only",
        "service": service_name,
        "normalized_event_count": len(rows),
        "security_events": events[:100],
        "authentication_failure_trend": _trend(events, "authentication_failure"),
        "authorization_denial_trend": _trend(events, "authorization_denied"),
        "network_analysis": network,
        "runtime_timeline": _timeline(rows, events),
        "classification": classification,
        "mitre_style_mapping": _mitre_mapping(rows, classification),
        "false_positive_analysis": false_positives,
        "blast_radius": blast,
        "security_hypotheses": _deterministic_hypotheses(rows, events, classification, false_positives),
        "next_best_evidence": _next_best_evidence(classification, events),
        "peer_security_context": peer,
        "handoff_candidates": handoffs[:6],
        "secret_token_policy": "only token/secret usage metadata may be analyzed; credential values are excluded from deterministic text and prompt projection",
    }
