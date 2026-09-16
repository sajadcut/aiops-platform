from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _labels(item: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = _raw(item)
    for value in (raw.get("labels"), item.get("labels")):
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
    parts = [
        item.get("name"), item.get("message"), item.get("value"),
        raw.get("diagnostic"), raw.get("event"), raw.get("reason"), raw.get("error"),
        raw.get("status"), raw.get("verdict"), raw.get("detail"),
    ]
    return " ".join(str(value) for value in parts if value not in (None, "")).lower()


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
    if normalized in {"1", "true", "yes", "up", "ok", "healthy", "success", "succeeded", "reachable", "open", "listening", "allowed"}:
        return True
    if normalized in {"0", "false", "no", "down", "failed", "failure", "unreachable", "closed", "not_listening", "denied", "blocked"}:
        return False
    return None


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
    name = str(item.get("name") or item.get("metric") or _lookup(item, "metric", "name", "item_key") or "").lower()
    value = item.get("value") if item.get("value") is not None else _lookup(item, "value", "current", "current_value")
    return name, _number(value)


def _ratio(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    if value > 1.5:
        return value / 100.0
    return value


def _source_destination(item: Mapping[str, Any]) -> Dict[str, Any]:
    source = _lookup(
        item, "source_endpoint", "source_host", "src_host", "source_ip", "src_ip",
        "source_service", "src_service", "source_pod", "src_pod", "client", "client_host",
    )
    destination = _lookup(
        item, "destination_endpoint", "destination_host", "dst_host", "destination_ip", "dst_ip",
        "destination_service", "dst_service", "destination_pod", "dst_pod", "target", "target_host",
        "server", "server_host",
    )
    protocol = _lookup(item, "protocol", "l4_protocol", "transport_protocol", "network_protocol")
    port = _lookup(item, "destination_port", "dst_port", "target_port", "service_port", "port")
    port_number = _number(port)
    name, _ = _metric(item)
    text = _text(item)
    if protocol in (None, ""):
        if "dns" in text or "dns" in name:
            protocol = "udp"
        elif any(token in text or token in name for token in ("tcp", "listener", "retrans", "syn", "reset")) or port_number is not None:
            protocol = "tcp"
    return {
        "source": str(source)[:240] if source not in (None, "") else "unknown",
        "destination": str(destination)[:240] if destination not in (None, "") else "unknown",
        "protocol": str(protocol).lower()[:40] if protocol not in (None, "") else "unknown",
        "port": int(port_number) if port_number is not None and port_number.is_integer() else port_number,
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
    stamps = sorted(timestamp for timestamp in (_timestamp(item) for item in items) if timestamp)
    return {
        "start": stamps[0].isoformat() if stamps else None,
        "end": stamps[-1].isoformat() if stamps else None,
    }


def _metric_matches(name: str, aliases: Sequence[str]) -> bool:
    return any(alias in name for alias in aliases)


METRIC_ALIASES: Dict[str, Tuple[str, ...]] = {
    "interface_up": ("interface_up", "link_up", "interface_state"),
    "interface_errors": ("interface_errors", "rx_errors", "tx_errors", "receive_errors", "transmit_errors"),
    "interface_drops": ("interface_drops", "rx_drops", "tx_drops", "packet_drops", "packets_dropped"),
    "packet_loss": ("packet_loss", "packet_loss_ratio", "icmp_loss"),
    "reachability": ("reachability", "reachable", "icmp_success", "ping_success"),
    "tcp_connect": ("tcp_connect", "connect_success", "tcp_probe_success"),
    "tcp_retransmission": ("tcp_retrans", "retransmission", "retransmits"),
    "tcp_resets": ("tcp_resets", "reset_rate", "connection_resets"),
    "syn_failures": ("syn_fail", "syn_failure", "syn_timeout"),
    "connection_timeouts": ("connection_timeout", "connect_timeout", "tcp_timeout"),
    "dns_latency": ("dns_latency", "dns_lookup_latency", "resolver_latency"),
    "http_latency": ("http_latency", "request_latency", "service_latency"),
    "bandwidth_utilization": ("bandwidth_utilization", "interface_utilization", "link_utilization", "network_utilization"),
    "packet_rate": ("packet_rate", "packets_per_second", "pps"),
    "queue_drops": ("queue_drop", "qdisc_drop", "queue_discards"),
    "conntrack_utilization": ("conntrack_utilization", "conntrack_usage", "nf_conntrack"),
}


def _feature_rows(items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    rows: Dict[str, List[Dict[str, Any]]] = {key: [] for key in METRIC_ALIASES}
    for index, item in enumerate(items):
        name, value = _metric(item)
        if not name:
            continue
        for feature, aliases in METRIC_ALIASES.items():
            if not _metric_matches(name, aliases):
                continue
            rows[feature].append({
                "evidence_id": _eid(item, index),
                "metric": name,
                "value": value,
                **_source_destination(item),
                "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
            })
    return rows


def _last_value(rows: Mapping[str, List[Dict[str, Any]]], feature: str) -> Optional[float]:
    feature_rows = rows.get(feature) or []
    if not feature_rows:
        return None
    return _number(feature_rows[-1].get("value"))


def _collect_explicit_states(items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {
        "route": [], "gateway": [], "reachability": [], "listener": [], "tcp": [],
        "dns": [], "http": [], "tls": [], "flows": [], "dependencies": [],
    }
    for index, item in enumerate(items):
        raw = _raw(item)
        text = _text(item)
        ctx = _source_destination(item)
        common = {
            "evidence_id": _eid(item, index),
            **ctx,
            "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
        }

        route_found = _bool(_lookup(item, "route_found", "has_route", "route_exists"))
        if route_found is not None or "no route to host" in text or "route missing" in text:
            result["route"].append({**common, "route_found": False if ("no route to host" in text or "route missing" in text) else route_found})

        gateway = _bool(_lookup(item, "gateway_reachable", "gateway_ok"))
        if gateway is not None:
            result["gateway"].append({**common, "gateway_reachable": gateway})

        reachable = _bool(_lookup(item, "reachable", "reachability", "ping_success"))
        if reachable is not None:
            result["reachability"].append({**common, "reachable": reachable})

        listening = _bool(_lookup(item, "listening", "listener_healthy", "port_open", "listener_present"))
        if listening is not None:
            result["listener"].append({**common, "listening": listening})

        tcp_status = _lookup(item, "tcp_status", "connect_status", "connection_state")
        if tcp_status not in (None, "") or any(token in text for token in ("connection refused", "connection reset", "connect timeout", "connection timeout", "syn timeout")):
            status = str(tcp_status or "").lower()
            if "connection refused" in text:
                status = "refused"
            elif "connection reset" in text:
                status = "reset"
            elif "timeout" in text and ("connect" in text or "connection" in text or "syn" in text):
                status = "timeout"
            result["tcp"].append({**common, "status": status or "unknown"})

        dns_status = _lookup(item, "dns_status", "rcode", "response_code", "lookup_status")
        dns_answer = _lookup(item, "dns_answer", "resolved_address", "record_value")
        expected = _lookup(item, "expected_address", "expected_record")
        resolver = _lookup(item, "resolver", "dns_resolver", "nameserver")
        if dns_status not in (None, "") or "nxdomain" in text or "servfail" in text or ("dns" in text and "timeout" in text):
            status = str(dns_status or "").upper()
            if "nxdomain" in text:
                status = "NXDOMAIN"
            elif "servfail" in text:
                status = "SERVFAIL"
            elif "timeout" in text:
                status = "TIMEOUT"
            result["dns"].append({
                **common, "status": status or "UNKNOWN", "answer": dns_answer,
                "expected": expected, "resolver": resolver,
                "query_name": _lookup(item, "query_name", "hostname", "record_name", "dns_name"),
            })
        if dns_answer not in (None, "") and expected not in (None, "") and str(dns_answer) != str(expected):
            result["dns"].append({
                **common, "status": "RECORD_MISMATCH", "answer": dns_answer,
                "expected": expected, "resolver": resolver,
                "query_name": _lookup(item, "query_name", "hostname", "record_name", "dns_name"),
            })

        http_status = _lookup(item, "http_status", "status_code")
        http_latency = _number(_lookup(item, "http_latency_ms", "latency_ms", "duration_ms"))
        if http_status not in (None, "") or http_latency is not None or "http" in text:
            result["http"].append({
                **common,
                "status": int(_number(http_status)) if _number(http_status) is not None else None,
                "latency_ms": http_latency,
            })

        tls_status = _lookup(item, "tls_status", "handshake_status")
        tls_error = _lookup(item, "tls_error", "certificate_error", "handshake_error")
        if tls_status not in (None, "") or tls_error not in (None, "") or any(
            token in text for token in ("tls handshake", "certificate verify", "certificate expired", "unknown ca", "ssl handshake")
        ):
            result["tls"].append({
                **common,
                "status": str(tls_status or "failed").lower(),
                "error": str(tls_error or text)[:300],
            })

        diagnostic = str(raw.get("diagnostic") or "").lower()
        verdict = str(_lookup(item, "verdict", "flow_verdict", "policy_verdict") or "").lower()
        flowish = diagnostic in {"flow", "network_flow", "ebpf_flow", "hubble_flow", "kubernetes_flow", "kafka_flow"} or any(
            key in raw for key in ("flow_verdict", "verdict", "bytes", "packets")
        )
        if flowish:
            denied = verdict in {"denied", "deny", "dropped", "drop", "blocked", "reject", "rejected"}
            result["flows"].append({
                **common, "verdict": verdict or "unknown", "denied": denied,
                "bytes": _number(_lookup(item, "bytes", "bytes_total")),
                "packets": _number(_lookup(item, "packets", "packet_count")),
                "service": _lookup(item, "service", "destination_service", "dst_service"),
                "flow_kind": diagnostic or "flow",
            })

        dependency_state = _lookup(item, "dependency_state", "downstream_state", "destination_health", "service_health")
        if dependency_state not in (None, "") or any(token in text for token in ("dependency outage", "downstream unavailable", "upstream unavailable")):
            result["dependencies"].append({
                **common, "state": str(dependency_state or "unavailable").lower(),
            })

    dns_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for row in result["dns"]:
        query_name = str(row.get("query_name") or "")
        answer = row.get("answer")
        resolver = row.get("resolver")
        if query_name and answer not in (None, "") and resolver not in (None, ""):
            dns_groups.setdefault((str(row.get("source") or "unknown"), query_name), []).append(row)
    for group in dns_groups.values():
        answers = {str(row.get("answer")) for row in group}
        resolvers = {str(row.get("resolver")) for row in group}
        if len(answers) > 1 and len(resolvers) > 1:
            for row in group:
                result["dns"].append({**row, "status": "RESOLVER_MISMATCH"})
    return result


def _layer_analysis(
    items: Sequence[Mapping[str, Any]],
    rows: Mapping[str, List[Dict[str, Any]]],
    states: Mapping[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    packet_loss = _last_value(rows, "packet_loss")
    retrans = _last_value(rows, "tcp_retransmission")
    bandwidth = _ratio(_last_value(rows, "bandwidth_utilization"))
    conntrack = _ratio(_last_value(rows, "conntrack_utilization"))
    queue_drops = _last_value(rows, "queue_drops")
    interface_up = _last_value(rows, "interface_up")
    interface_errors = _last_value(rows, "interface_errors")
    interface_drops = _last_value(rows, "interface_drops")
    tcp_connect = _last_value(rows, "tcp_connect")
    tcp_resets = _last_value(rows, "tcp_resets")
    syn_failures = _last_value(rows, "syn_failures")
    timeouts = _last_value(rows, "connection_timeouts")
    dns_latency = _last_value(rows, "dns_latency")
    http_latency = _last_value(rows, "http_latency")
    pps = _last_value(rows, "packet_rate")

    return {
        "l2_l3": {
            "interface_up": interface_up,
            "interface_errors": interface_errors,
            "interface_drops": interface_drops,
            "packet_loss": packet_loss,
            "routes": states["route"][:20],
            "gateways": states["gateway"][:20],
            "reachability": states["reachability"][:20],
        },
        "l4": {
            "tcp_connect": tcp_connect,
            "tcp_retransmission": retrans,
            "tcp_resets": tcp_resets,
            "syn_failures": syn_failures,
            "connection_timeouts": timeouts,
            "listeners": states["listener"][:20],
            "tcp_events": states["tcp"][:20],
        },
        "dns": {
            "events": states["dns"][:30],
            "latency_ms": dns_latency,
        },
        "l7": {
            "http": states["http"][:30],
            "http_latency_ms": http_latency,
            "tls": states["tls"][:20],
        },
        "capacity": {
            "bandwidth_utilization": bandwidth,
            "packet_rate": pps,
            "queue_drops": queue_drops,
            "conntrack_utilization": conntrack,
        },
        "flows": states["flows"][:40],
        "dependencies": states["dependencies"][:20],
    }


def _path_records(items: Sequence[Mapping[str, Any]], states: Mapping[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[str, str, str, Any], Dict[str, Any]] = {}
    for index, item in enumerate(items):
        ctx = _source_destination(item)
        key = (ctx["source"], ctx["destination"], ctx["protocol"], ctx["port"])
        group = groups.setdefault(key, {
            **ctx, "evidence_ids": [], "timestamps": [], "signals": [],
        })
        eid = _eid(item, index)
        if eid not in group["evidence_ids"]:
            group["evidence_ids"].append(eid)
        stamp = _timestamp(item)
        if stamp:
            group["timestamps"].append(stamp.isoformat())
        text = _text(item)
        if text:
            group["signals"].append(text[:220])
    result: List[Dict[str, Any]] = []
    for group in groups.values():
        timestamps = sorted(group.pop("timestamps"))
        result.append({
            **group,
            "time_window": {
                "start": timestamps[0] if timestamps else None,
                "end": timestamps[-1] if timestamps else None,
            },
            "signals": group["signals"][:8],
        })
    result.sort(key=lambda row: len(row["evidence_ids"]), reverse=True)
    return result[:30]


def _context_for_ids(
    evidence_context: Mapping[str, Dict[str, Any]],
    evidence_ids: Iterable[Any],
    default_window: Mapping[str, Any],
) -> Dict[str, Any]:
    contexts = [evidence_context[str(eid)] for eid in evidence_ids if str(eid) in evidence_context]
    if not contexts:
        return {
            "source": "unknown", "destination": "unknown", "protocol": "unknown", "port": None,
            "time_window": dict(default_window),
        }

    def common(key: str, unknown: Any) -> Any:
        values = [ctx.get(key) for ctx in contexts if ctx.get(key) not in (None, "", "unknown")]
        if not values:
            return unknown
        unique = list(dict.fromkeys(values))
        return unique[0] if len(unique) == 1 else "multiple"

    stamps = [ctx.get("timestamp") for ctx in contexts if ctx.get("timestamp")]
    return {
        "source": common("source", "unknown"),
        "destination": common("destination", "unknown"),
        "protocol": common("protocol", "unknown"),
        "port": common("port", None),
        "time_window": {
            "start": min(stamps) if stamps else default_window.get("start"),
            "end": max(stamps) if stamps else default_window.get("end"),
        },
    }


_EXPECTED_FALSIFICATION = {
    "dns": "DNS resolution from the affected source returns the expected record without NXDOMAIN, SERVFAIL, timeout or resolver divergence during the incident window.",
    "routing": "A route and reachable gateway/path exist from the affected source to the destination throughout the incident window.",
    "firewall_policy": "Policy/firewall evidence shows the same source-destination-protocol-port flow is allowed and packets traverse the path without deny/drop verdicts.",
    "listener_service": "The destination is listening on the expected protocol/port and a direct connect from the affected source succeeds.",
    "packet_loss": "Packet loss, interface drops and retransmissions return to baseline while the same source-destination flow is exercised.",
    "congestion": "Bandwidth/packet rate/queue and conntrack pressure stay below saturation while latency and drops persist on the same path.",
    "tls_identity": "TCP connectivity succeeds and the TLS handshake validates the expected identity/certificate without handshake errors.",
    "application_timeout": "DNS, route, listener and TCP path remain healthy while application/L7 response time reproduces the timeout or slow response.",
    "dependency_outage": "The downstream destination reports healthy service state and successful service-to-service requests while the caller symptom persists.",
    "network_healthy": "Lower-layer path, DNS and TCP checks remain healthy under the same source-destination load while the incident symptom persists elsewhere.",
}


def _cause_candidates(
    items: Sequence[Mapping[str, Any]],
    rows: Mapping[str, List[Dict[str, Any]]],
    states: Mapping[str, List[Dict[str, Any]]],
    layers: Mapping[str, Any],
    evidence_context: Mapping[str, Dict[str, Any]],
    default_window: Mapping[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    candidates: List[Dict[str, Any]] = []
    uncertain: List[Dict[str, Any]] = []

    def add(code: str, evidence_ids: Iterable[Any], *, handoff: Optional[str], basis: str) -> None:
        ids = list(dict.fromkeys(str(value) for value in evidence_ids if value not in (None, "")))[:20]
        context = _context_for_ids(evidence_context, ids, default_window)
        candidates.append({
            "code": code,
            "evidence_ids": ids,
            "handoff": handoff,
            "basis": basis,
            "root_cause_status": "candidate_requires_falsification",
            **context,
            "expected_falsification_result": _EXPECTED_FALSIFICATION[code],
        })

    dns_bad = [
        row for row in states["dns"]
        if str(row.get("status") or "").upper() in {"NXDOMAIN", "SERVFAIL", "TIMEOUT", "RECORD_MISMATCH", "RESOLVER_MISMATCH"}
    ]
    if dns_bad:
        add("dns", [row["evidence_id"] for row in dns_bad], handoff=None, basis="explicit DNS response failure, timeout or record mismatch")

    route_bad = [row for row in states["route"] if row.get("route_found") is False]
    gateway_bad = [row for row in states["gateway"] if row.get("gateway_reachable") is False]
    reach_bad = [row for row in states["reachability"] if row.get("reachable") is False]
    interface_down = [
        row for row in rows.get("interface_up", [])
        if (_number(row.get("value")) is not None and _number(row.get("value")) <= 0)
    ]
    if route_bad or gateway_bad or interface_down:
        add(
            "routing",
            [row["evidence_id"] for row in route_bad + gateway_bad + interface_down],
            handoff="infrastructure",
            basis="L2/L3 interface, route or gateway failure from the affected source",
        )
    elif reach_bad and states["route"]:
        add("routing", [row["evidence_id"] for row in reach_bad], handoff="infrastructure", basis="destination path is unreachable despite explicit route observations")

    denied = [row for row in states["flows"] if row.get("denied")]
    if denied:
        add("firewall_policy", [row["evidence_id"] for row in denied], handoff="security", basis="explicit denied/dropped flow verdict")

    refused = [row for row in states["tcp"] if row.get("status") in {"refused", "closed"}]
    listener_bad = [row for row in states["listener"] if row.get("listening") is False]
    if refused or listener_bad:
        add("listener_service", [row["evidence_id"] for row in refused + listener_bad], handoff="application", basis="connection refused/closed or destination listener absent")

    packet_loss = _last_value(rows, "packet_loss")
    retrans = _last_value(rows, "tcp_retransmission")
    interface_drops = _last_value(rows, "interface_drops")
    packet_ids = [
        row["evidence_id"] for key in ("packet_loss", "tcp_retransmission", "interface_drops")
        for row in rows.get(key, [])
    ]
    if ((packet_loss is not None and packet_loss >= 0.02) or
        (retrans is not None and retrans >= 0.02) or
        (interface_drops is not None and interface_drops > 0)):
        add("packet_loss", packet_ids, handoff="infrastructure", basis="loss/drop/retransmission evidence on the observed path")

    bandwidth = layers["capacity"].get("bandwidth_utilization")
    queue_drops = layers["capacity"].get("queue_drops")
    conntrack = layers["capacity"].get("conntrack_utilization")
    if (
        (bandwidth is not None and bandwidth >= 0.9 and (queue_drops or 0) > 0)
        or (conntrack is not None and conntrack >= 0.9)
    ):
        ids = [
            row["evidence_id"] for key in ("bandwidth_utilization", "queue_drops", "conntrack_utilization", "packet_rate")
            for row in rows.get(key, [])
        ]
        add("congestion", ids, handoff="infrastructure", basis="bandwidth/queue or conntrack pressure indicates path capacity saturation")

    tls_bad = [
        row for row in states["tls"]
        if row.get("status") not in {"ok", "success", "healthy", "valid"} or row.get("error")
    ]
    if tls_bad:
        add("tls_identity", [row["evidence_id"] for row in tls_bad], handoff="identity", basis="TLS handshake or certificate identity failure")

    dependency_bad = [
        row for row in states["dependencies"]
        if row.get("state") in {"down", "failed", "unavailable", "degraded", "unhealthy", "timeout"}
    ]
    if dependency_bad:
        add("dependency_outage", [row["evidence_id"] for row in dependency_bad], handoff="dependency", basis="explicit downstream dependency health failure")

    lower_layer_fault_codes = {row["code"] for row in candidates if row["code"] in {"dns", "routing", "firewall_policy", "listener_service", "packet_loss", "congestion", "tls_identity"}}
    http_slow = [
        row for row in states["http"]
        if (row.get("latency_ms") is not None and float(row["latency_ms"]) >= 1000)
        or (row.get("status") is not None and int(row["status"]) >= 500)
    ]
    timeout_rows = [row for row in states["tcp"] if row.get("status") == "timeout"]
    timeout_metric_ids = [
        row["evidence_id"] for row in rows.get("connection_timeouts", []) if (_number(row.get("value")) or 0) > 0
    ]
    lower_healthy = (
        (any(row.get("route_found") is True for row in states["route"]) or not states["route"])
        and (not states["reachability"] or any(row.get("reachable") is True for row in states["reachability"]))
        and (not states["listener"] or any(row.get("listening") is True for row in states["listener"]))
        and (not states["tcp"] or any(row.get("status") in {"ok", "success", "connected", "open"} for row in states["tcp"]))
    )
    if http_slow and not lower_layer_fault_codes and lower_healthy:
        add("application_timeout", [row["evidence_id"] for row in http_slow], handoff="application", basis="L7 response failure/latency with no corroborating lower-layer fault")

    timeout_ids = [row["evidence_id"] for row in timeout_rows] + timeout_metric_ids
    if timeout_ids and not any(row["code"] in {"routing", "firewall_policy", "listener_service", "packet_loss", "congestion", "dns", "tls_identity"} for row in candidates):
        context = _context_for_ids(evidence_context, timeout_ids, default_window)
        uncertain.append({
            "code": "connection_timeout_requires_layer_localization",
            "evidence_ids": list(dict.fromkeys(timeout_ids)),
            **context,
            "interpretation": "connection timeout alone is not sufficient to declare a network root cause",
            "expected_falsification_result": "Collect route/gateway, policy/flow, listener, packet-loss/retransmission and DNS evidence for the same source-destination-protocol-port tuple.",
        })

    explicit_healthy = (
        (not states["route"] or any(row.get("route_found") is True for row in states["route"]))
        and (not states["gateway"] or any(row.get("gateway_reachable") is True for row in states["gateway"]))
        and (not states["reachability"] or any(row.get("reachable") is True for row in states["reachability"]))
        and (packet_loss is None or packet_loss < 0.01)
        and (retrans is None or retrans < 0.01)
        and (not states["dns"] or all(str(row.get("status") or "").upper() in {"NOERROR", "SUCCESS", "OK"} for row in states["dns"]))
        and (not states["listener"] or any(row.get("listening") is True for row in states["listener"]))
        and (not states["tcp"] or any(row.get("status") in {"ok", "success", "connected", "open"} for row in states["tcp"]))
    )
    if explicit_healthy and not candidates and not uncertain and any(
        states[key] for key in ("route", "gateway", "reachability", "dns", "listener", "tcp")
    ):
        ids = [
            row["evidence_id"] for key in ("route", "gateway", "reachability", "dns", "listener", "tcp")
            for row in states[key]
        ]
        add("network_healthy", ids, handoff="application", basis="explicit lower-layer path, DNS and TCP evidence is healthy")

    return candidates[:16], uncertain[:8]


def build_network_reliability_analysis(
    evidence: Iterable[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    ctx = context if isinstance(context, Mapping) else {}
    default_window = _window(items, ctx)
    rows = _feature_rows(items)
    states = _collect_explicit_states(items)
    layers = _layer_analysis(items, rows, states)
    paths = _path_records(items, states)

    evidence_context: Dict[str, Dict[str, Any]] = {}
    for index, item in enumerate(items):
        eid = _eid(item, index)
        evidence_context[eid] = {
            **_source_destination(item),
            "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
        }

    candidates, uncertain = _cause_candidates(items, rows, states, layers, evidence_context, default_window)
    handoffs: List[str] = []
    for candidate in candidates:
        target = candidate.get("handoff")
        if target and target != "network" and target not in handoffs:
            handoffs.append(str(target))

    gaps: List[Dict[str, Any]] = []
    if not paths or all(path["source"] == "unknown" or path["destination"] == "unknown" for path in paths):
        gaps.append({"evidence": "source-to-destination tuple with protocol and port", "information_gain": 0.99})
    if not states["route"] and not states["gateway"]:
        gaps.append({"evidence": "route and gateway state from the affected source", "information_gain": 0.94})
    if not states["tcp"] and not rows["tcp_connect"]:
        gaps.append({"evidence": "TCP connect result for the same source-destination-port tuple", "information_gain": 0.93})
    if not states["dns"]:
        gaps.append({"evidence": "DNS response code, resolver, latency and returned record from the affected source", "information_gain": 0.88})
    if not states["listener"]:
        gaps.append({"evidence": "destination listener/service state for the expected port", "information_gain": 0.87})
    if not states["flows"]:
        gaps.append({"evidence": "flow/policy verdicts when Kubernetes or eBPF telemetry is available", "information_gain": 0.83})
    if not rows["packet_loss"] and not rows["tcp_retransmission"]:
        gaps.append({"evidence": "packet loss/retransmission for the affected path", "information_gain": 0.8})
    gaps.sort(key=lambda row: float(row["information_gain"]), reverse=True)

    return {
        "policy": "connection timeout alone is not a network root cause; localize the failing layer on the affected source-to-destination path",
        "service": service_name,
        "time_window": default_window,
        "layers": layers,
        "path_analysis": paths,
        "cause_candidates": candidates,
        "uncertain_observations": uncertain,
        "network_hypotheses": candidates,
        "handoff_candidates": handoffs[:8],
        "evidence_gaps": gaps[:8],
        "next_best_evidence": gaps[:6],
        "evidence_path_context": evidence_context,
        "analysis_stages": ["l2_l3", "l4", "dns", "l7", "capacity", "source_destination_path", "flow_policy", "cross_layer_falsification"],
    }
