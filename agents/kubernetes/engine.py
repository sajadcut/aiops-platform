from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

SUPPORTED_KINDS = (
    "pod", "replicaset", "deployment", "statefulset", "daemonset", "job", "cronjob",
    "node", "service", "endpoint", "endpointslice", "ingress", "persistentvolumeclaim",
    "persistentvolume", "horizontalpodautoscaler", "poddisruptionbudget", "networkpolicy",
    "configmap", "secret", "validatingwebhookconfiguration", "mutatingwebhookconfiguration",
    "event",
)
_SECRET_FIELDS = {"data", "stringdata", "binarydata", "token", "password", "secret", "valuefrom"}


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _resource(item: Mapping[str, Any]) -> Mapping[str, Any]:
    for value in (
        item.get("resource"), item.get("object"), _raw(item).get("resource"),
        _raw(item).get("object"), _raw(item),
    ):
        if isinstance(value, Mapping) and (
            value.get("kind") or value.get("apiVersion") or value.get("metadata")
            or value.get("spec") or value.get("status")
        ):
            return value
    return {}


def _metadata(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("metadata")
    return value if isinstance(value, Mapping) else {}


def _spec(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("spec")
    return value if isinstance(value, Mapping) else {}


def _status(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("status")
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


def _timestamp(item: Mapping[str, Any], resource: Optional[Mapping[str, Any]] = None) -> Optional[datetime]:
    resource = resource or _resource(item)
    metadata = _metadata(resource)
    for value in (
        item.get("observed_at"), item.get("timestamp"), item.get("created_at"),
        _raw(item).get("timestamp"), metadata.get("creationTimestamp"),
    ):
        parsed = _parse_time(value)
        if parsed:
            return parsed
    return None


def _text(value: Any, depth: int = 0) -> str:
    if depth > 4:
        return ""
    if isinstance(value, str):
        return value[:800]
    if isinstance(value, Mapping):
        parts: List[str] = []
        for key, current in list(value.items())[:80]:
            normalized = str(key).lower().replace("-", "").replace("_", "")
            if normalized in _SECRET_FIELDS or any(token in normalized for token in ("password", "token", "secretdata")):
                continue
            part = _text(current, depth + 1)
            if part:
                parts.append(part)
        return " ".join(parts)
    if isinstance(value, (list, tuple)):
        return " ".join(_text(current, depth + 1) for current in list(value)[:30])
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def _kind(item: Mapping[str, Any]) -> str:
    resource = _resource(item)
    raw_kind = resource.get("kind") or item.get("kind") or _raw(item).get("kind")
    if raw_kind:
        normalized = re.sub(r"[^a-z]", "", str(raw_kind).lower())
        aliases = {
            "pvc": "persistentvolumeclaim", "pv": "persistentvolume",
            "hpa": "horizontalpodautoscaler", "pdb": "poddisruptionbudget",
            "endpoints": "endpoint", "validatingwebhook": "validatingwebhookconfiguration",
            "mutatingwebhook": "mutatingwebhookconfiguration",
        }
        return aliases.get(normalized, normalized)
    text = f" {_text(item).lower()} "
    patterns = (
        ("endpointslice", ("endpointslice",)),
        ("persistentvolumeclaim", ("persistentvolumeclaim", " pvc ")),
        ("persistentvolume", ("persistentvolume", " pv ")),
        ("horizontalpodautoscaler", ("horizontalpodautoscaler", " hpa ")),
        ("poddisruptionbudget", ("poddisruptionbudget", " pdb ")),
        ("networkpolicy", ("networkpolicy", "network policy")),
        ("statefulset", ("statefulset",)), ("daemonset", ("daemonset",)),
        ("replicaset", ("replicaset",)), ("cronjob", ("cronjob",)),
        ("deployment", ("deployment",)), ("ingress", ("ingress",)),
        ("service", ("service",)), ("endpoint", ("endpoint",)),
        ("configmap", ("configmap",)), ("secret", ("secret",)),
        ("node", ("node",)), ("pod", ("pod", "container")), ("job", ("job",)),
    )
    for kind, tokens in patterns:
        if any(token in text for token in tokens):
            return kind
    if str(item.get("type") or "").lower() in {"event", "alert"}:
        return "event"
    return "unknown"


def _name_namespace(item: Mapping[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    resource = _resource(item)
    meta = _metadata(resource)
    name = meta.get("name") or item.get("resource_name") or item.get("name")
    namespace = meta.get("namespace") or item.get("namespace") or _raw(item).get("namespace")
    return (str(name) if name not in (None, "") else None, str(namespace) if namespace not in (None, "") else None)


def _condition_map(status: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    value = status.get("conditions")
    if isinstance(value, list):
        for row in value:
            if isinstance(row, Mapping) and row.get("type"):
                result[str(row["type"])] = {
                    "status": row.get("status"), "reason": row.get("reason"),
                    "message": row.get("message"), "last_transition_time": row.get("lastTransitionTime"),
                }
    return result


def _owner(resource: Mapping[str, Any]) -> Optional[Dict[str, str]]:
    refs = _metadata(resource).get("ownerReferences")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, Mapping) and ref.get("kind") and ref.get("name"):
                return {"kind": str(ref["kind"]).lower(), "name": str(ref["name"])}
    return None


def _labels(resource: Mapping[str, Any]) -> Dict[str, str]:
    value = _metadata(resource).get("labels")
    if not isinstance(value, Mapping):
        return {}
    return {str(k): str(v) for k, v in list(value.items())[:40]}


def _selector(spec: Mapping[str, Any]) -> Dict[str, str]:
    value = spec.get("selector")
    if isinstance(value, Mapping) and isinstance(value.get("matchLabels"), Mapping):
        value = value["matchLabels"]
    if not isinstance(value, Mapping):
        return {}
    return {str(k): str(v) for k, v in list(value.items())[:40] if not isinstance(v, (Mapping, list))}


def _selector_matches(selector: Mapping[str, str], labels: Mapping[str, str]) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def _safe_metadata(resource: Mapping[str, Any]) -> Dict[str, Any]:
    meta = _metadata(resource)
    annotations = meta.get("annotations") if isinstance(meta.get("annotations"), Mapping) else {}
    return {
        "name": meta.get("name"), "namespace": meta.get("namespace"), "uid": meta.get("uid"),
        "generation": meta.get("generation"), "resource_version": meta.get("resourceVersion"),
        "labels": dict(list(_labels(resource).items())[:20]),
        "annotations_keys": sorted(str(k) for k in annotations.keys())[:30],
    }


def _numeric(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip().rstrip("%"))
    except ValueError:
        return None


def _cpu_quantity(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    try:
        if text.endswith("m"):
            return float(text[:-1]) / 1000.0
        if text.endswith("u"):
            return float(text[:-1]) / 1_000_000.0
        if text.endswith("n"):
            return float(text[:-1]) / 1_000_000_000.0
        return float(text)
    except ValueError:
        return None


def _bytes_quantity(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    match = re.fullmatch(r"([-+]?\d+(?:\.\d+)?)([KMGTEP]i|[kMGTPE]|KiB|MiB|GiB|TiB|PiB|EiB)?", text)
    if not match:
        return None
    number = float(match.group(1))
    suffix = match.group(2) or ""
    binary = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4, "Pi": 1024**5, "Ei": 1024**6,
              "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4, "PiB": 1024**5, "EiB": 1024**6}
    decimal = {"k": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4, "P": 1000**5, "E": 1000**6}
    return number * binary.get(suffix, decimal.get(suffix, 1))


def _finding(code: str, severity: str, message: str, evidence_ids: Iterable[str],
             resource_kind: str, resource_name: Optional[str], anomaly_start: Optional[str] = None,
             handoff: Optional[str] = None, details: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    return {
        "code": code, "severity": severity, "message": message,
        "resource_kind": resource_kind, "resource_name": resource_name,
        "evidence_ids": list(dict.fromkeys(str(x) for x in evidence_ids if x)),
        "anomaly_start": anomaly_start, "handoff": handoff, "details": dict(details or {}),
    }


def _row_base(item: Mapping[str, Any], index: int) -> Dict[str, Any]:
    resource = _resource(item)
    name, namespace = _name_namespace(item)
    stamp = _timestamp(item, resource)
    return {
        "evidence_id": _eid(item, index), "kind": _kind(item), "name": name,
        "namespace": namespace, "timestamp": stamp.isoformat() if stamp else None,
        "resource": resource, "text": _text(item).lower(),
    }


def _pod_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    resource = row["resource"]
    spec, status = _spec(resource), _status(resource)
    name = row.get("name")
    conditions = _condition_map(status)
    findings: List[Dict[str, Any]] = []
    signals: List[str] = []
    phase = str(status.get("phase") or "").lower()
    reason = str(status.get("reason") or "")
    text = row["text"]
    eid, stamp = row["evidence_id"], row.get("timestamp")

    if phase == "pending":
        message = reason or conditions.get("PodScheduled", {}).get("reason") or "Pod Pending"
        findings.append(_finding("pod_pending", "medium", f"Pod {name or ''} is Pending: {message}", [eid], "pod", name, stamp))
        signals.append("pending")
    if any(token in text for token in ("failedscheduling", "failed scheduling", "unschedulable")):
        findings.append(_finding("failed_scheduling", "high", "Pod scheduling failed", [eid], "pod", name, stamp))
        signals.append("failed_scheduling")
    if any(token in text for token in ("insufficient cpu", "insufficient memory")):
        details = {"insufficient_cpu": "insufficient cpu" in text, "insufficient_memory": "insufficient memory" in text}
        findings.append(_finding("insufficient_resources", "high", "Scheduler reports insufficient node resources", [eid], "pod", name, stamp, "infrastructure", details))
    if any(token in text for token in ("node affinity", "pod affinity", "anti-affinity", "nodeaffinity", "podantiaffinity")):
        findings.append(_finding("affinity_constraint", "medium", "Affinity/anti-affinity contributes to scheduling constraints", [eid], "pod", name, stamp))
    if any(token in text for token in ("taint", "toleration")) and any(token in text for token in ("untolerated", "didn't tolerate", "does not tolerate")):
        findings.append(_finding("taint_toleration_mismatch", "medium", "Pod does not tolerate a required node taint", [eid], "pod", name, stamp))
    if any(token in text for token in ("imagepullbackoff", "errimagepull", "failed to pull image")):
        findings.append(_finding("image_pull_failure", "high", "Container image pull failure observed", [eid], "pod", name, stamp, "change"))
    if "crashloopbackoff" in text or "back-off restarting failed container" in text or "backoff restarting failed container" in text:
        findings.append(_finding("crashloopbackoff", "high", "Container restart backoff/CrashLoopBackOff observed", [eid], "pod", name, stamp))
        signals.append("crashloopbackoff")

    statuses: List[Mapping[str, Any]] = []
    for key in ("containerStatuses", "initContainerStatuses"):
        value = status.get(key)
        if isinstance(value, list):
            statuses.extend(v for v in value if isinstance(v, Mapping))
    restart_count = 0
    for container in statuses:
        cname = str(container.get("name") or "")
        restart_count += int(container.get("restartCount") or 0)
        last_state = container.get("lastState") if isinstance(container.get("lastState"), Mapping) else {}
        state = container.get("state") if isinstance(container.get("state"), Mapping) else {}
        terminated = last_state.get("terminated") if isinstance(last_state.get("terminated"), Mapping) else None
        if terminated is None and isinstance(state.get("terminated"), Mapping):
            terminated = state.get("terminated")
        waiting = state.get("waiting") if isinstance(state.get("waiting"), Mapping) else {}
        if str(waiting.get("reason") or "") == "CrashLoopBackOff":
            findings.append(_finding("crashloopbackoff", "high", f"Container {cname} is in CrashLoopBackOff", [eid], "pod", name, stamp))
        if isinstance(terminated, Mapping):
            term_reason = str(terminated.get("reason") or "")
            exit_code = terminated.get("exitCode")
            if term_reason == "OOMKilled":
                findings.append(_finding("oomkilled", "high", f"Container {cname} was OOMKilled", [eid], "pod", name, stamp, None, {"exit_code": exit_code}))
                signals.append("oomkilled")
            elif exit_code not in (None, 0):
                findings.append(_finding("nonzero_exit", "medium", f"Container {cname} exited with code {exit_code}", [eid], "pod", name, stamp, None, {"exit_code": exit_code}))
    if restart_count >= 3:
        findings.append(_finding("restart_trend", "medium", f"Pod restart count is {restart_count}", [eid], "pod", name, stamp, None, {"restart_count": restart_count}))

    for probe in ("readiness", "liveness", "startup"):
        if f"{probe} probe failed" in text or (f"{probe} probe" in text and "failed" in text):
            findings.append(_finding(f"{probe}_probe_failure", "high" if probe != "startup" else "medium", f"{probe.capitalize()} probe failure observed", [eid], "pod", name, stamp))
            signals.append(f"{probe}_probe_failure")
    if "evicted" in text or str(status.get("reason") or "").lower() == "evicted":
        findings.append(_finding("pod_evicted", "high", "Pod eviction observed", [eid], "pod", name, stamp, "infrastructure"))

    volumes: List[str] = []
    for volume in spec.get("volumes") or []:
        if isinstance(volume, Mapping) and isinstance(volume.get("persistentVolumeClaim"), Mapping):
            claim = volume["persistentVolumeClaim"].get("claimName")
            if claim:
                volumes.append(str(claim))
    containers: List[Dict[str, Any]] = []
    for container in spec.get("containers") or []:
        if not isinstance(container, Mapping):
            continue
        resources = container.get("resources") if isinstance(container.get("resources"), Mapping) else {}
        requests = resources.get("requests") if isinstance(resources.get("requests"), Mapping) else {}
        limits = resources.get("limits") if isinstance(resources.get("limits"), Mapping) else {}
        containers.append({
            "name": container.get("name"),
            "requests": {"cpu": requests.get("cpu"), "memory": requests.get("memory")},
            "limits": {"cpu": limits.get("cpu"), "memory": limits.get("memory")},
        })
    ready = conditions.get("Ready", {}).get("status")
    return {
        "kind": "pod", "name": name, "namespace": row.get("namespace"), "evidence_ids": [eid],
        "health": "degraded" if findings else ("healthy" if phase == "running" and str(ready).lower() == "true" else "unknown"),
        "phase": status.get("phase"), "node": spec.get("nodeName"), "owner": _owner(resource),
        "labels": _labels(resource), "pvc_claims": volumes, "containers": containers,
        "restart_count": restart_count, "conditions": conditions, "signals": sorted(set(signals)), "findings": findings,
    }


def _controller_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    resource, kind = row["resource"], row["kind"]
    spec, status = _spec(resource), _status(resource)
    name, eid, stamp = row.get("name"), row["evidence_id"], row.get("timestamp")
    findings: List[Dict[str, Any]] = []
    generation = _metadata(resource).get("generation")
    observed = status.get("observedGeneration")
    if generation is not None and observed is not None and str(generation) != str(observed):
        findings.append(_finding("generation_mismatch", "medium", f"{kind} observedGeneration lags metadata generation", [eid], kind, name, stamp, "change", {"generation": generation, "observed_generation": observed}))
    desired = spec.get("replicas")
    ready = status.get("readyReplicas")
    available = status.get("availableReplicas")
    unavailable = status.get("unavailableReplicas")
    current = status.get("currentReplicas") or status.get("replicas")
    if unavailable not in (None, 0, "0"):
        findings.append(_finding("unavailable_replicas", "high", f"{kind} has unavailable replicas", [eid], kind, name, stamp, None, {"desired": desired, "ready": ready, "available": available, "unavailable": unavailable}))
    if desired not in (None, 0) and ready is not None:
        try:
            if float(ready) < float(desired):
                findings.append(_finding("replica_shortfall", "medium", f"{kind} ready replicas are below desired", [eid], kind, name, stamp, None, {"desired": desired, "ready": ready}))
        except (TypeError, ValueError):
            pass
    text = row["text"]
    if any(token in text for token in ("progressdeadlineexceeded", "rollout stalled", "failed rollout")):
        findings.append(_finding("rollout_stalled", "high", f"{kind} rollout is stalled", [eid], kind, name, stamp, "change"))
    if kind == "statefulset" and status.get("currentRevision") and status.get("updateRevision") and status.get("currentRevision") != status.get("updateRevision"):
        findings.append(_finding("statefulset_revision_mismatch", "medium", "StatefulSet has mixed current/update revisions", [eid], kind, name, stamp, "change"))
    if kind == "job" and status.get("failed"):
        findings.append(_finding("job_failed", "high", f"Job has {status.get('failed')} failed pod(s)", [eid], kind, name, stamp))
    if kind == "cronjob" and ("missed schedule" in text or "failedneedsstart" in text):
        findings.append(_finding("cronjob_schedule_failure", "medium", "CronJob missed or failed schedule", [eid], kind, name, stamp))
    return {
        "kind": kind, "name": name, "namespace": row.get("namespace"), "evidence_ids": [eid],
        "health": "degraded" if findings else "healthy", "owner": _owner(resource), "selector": _selector(spec),
        "desired_replicas": desired, "current_replicas": current, "ready_replicas": ready,
        "available_replicas": available, "unavailable_replicas": unavailable,
        "generation": generation, "observed_generation": observed, "findings": findings,
    }


def _node_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    resource = row["resource"]
    spec, status = _spec(resource), _status(resource)
    name, eid, stamp = row.get("name"), row["evidence_id"], row.get("timestamp")
    conditions = _condition_map(status)
    findings: List[Dict[str, Any]] = []
    ready = str(conditions.get("Ready", {}).get("status") or "").lower()
    if ready and ready != "true":
        findings.append(_finding("node_not_ready", "critical", "Node is not Ready", [eid], "node", name, stamp, "infrastructure"))
    for ctype in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
        if str(conditions.get(ctype, {}).get("status") or "").lower() == "true":
            handoff = "network" if ctype == "NetworkUnavailable" else "infrastructure"
            findings.append(_finding("node_pressure", "high", f"Node condition {ctype}=True", [eid], "node", name, stamp, handoff, {"condition": ctype}))
    if spec.get("unschedulable"):
        findings.append(_finding("node_unschedulable", "medium", "Node is marked unschedulable", [eid], "node", name, stamp, "infrastructure"))
    if "eviction" in row["text"] or "evicted" in row["text"]:
        findings.append(_finding("node_eviction_pressure", "high", "Node eviction activity observed", [eid], "node", name, stamp, "infrastructure"))
    return {
        "kind": "node", "name": name, "evidence_ids": [eid],
        "health": "degraded" if findings else ("healthy" if ready == "true" else "unknown"),
        "conditions": conditions, "unschedulable": bool(spec.get("unschedulable")), "findings": findings,
    }


def _service_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    spec = _spec(row["resource"])
    return {"kind": "service", "name": row.get("name"), "namespace": row.get("namespace"), "evidence_ids": [row["evidence_id"]], "health": "unknown", "selector": _selector(spec), "ports": [dict(p) for p in (spec.get("ports") or []) if isinstance(p, Mapping)][:12], "findings": []}


def _endpoint_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    resource, kind = row["resource"], row["kind"]
    name, eid, stamp = row.get("name"), row["evidence_id"], row.get("timestamp")
    ready = 0
    total = 0
    target_refs: List[Dict[str, Any]] = []
    if kind == "endpointslice":
        for endpoint in resource.get("endpoints") or []:
            if not isinstance(endpoint, Mapping):
                continue
            total += 1
            conditions = endpoint.get("conditions") if isinstance(endpoint.get("conditions"), Mapping) else {}
            if conditions.get("ready") is not False:
                ready += 1
            ref = endpoint.get("targetRef")
            if isinstance(ref, Mapping):
                target_refs.append({"kind": ref.get("kind"), "name": ref.get("name")})
    else:
        for subset in resource.get("subsets") or []:
            if not isinstance(subset, Mapping):
                continue
            for address in subset.get("addresses") or []:
                if not isinstance(address, Mapping):
                    continue
                total += 1
                ready += 1
                ref = address.get("targetRef")
                if isinstance(ref, Mapping):
                    target_refs.append({"kind": ref.get("kind"), "name": ref.get("name")})
            total += len([x for x in subset.get("notReadyAddresses") or [] if isinstance(x, Mapping)])
    findings: List[Dict[str, Any]] = []
    if total == 0 or ready == 0:
        findings.append(_finding("no_ready_endpoints", "high", f"{kind} has no ready endpoint", [eid], kind, name, stamp))
    return {"kind": kind, "name": name, "namespace": row.get("namespace"), "evidence_ids": [eid], "health": "degraded" if findings else "healthy", "ready_endpoints": ready, "total_endpoints": total, "target_refs": target_refs, "findings": findings}


def _ingress_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    spec = _spec(row["resource"])
    backends: List[str] = []
    default = spec.get("defaultBackend")
    if isinstance(default, Mapping) and isinstance(default.get("service"), Mapping) and default["service"].get("name"):
        backends.append(str(default["service"]["name"]))
    for rule in spec.get("rules") or []:
        if not isinstance(rule, Mapping) or not isinstance(rule.get("http"), Mapping):
            continue
        for path in rule["http"].get("paths") or []:
            backend = path.get("backend") if isinstance(path, Mapping) else None
            service = backend.get("service") if isinstance(backend, Mapping) else None
            if isinstance(service, Mapping) and service.get("name"):
                backends.append(str(service["name"]))
    return {"kind": "ingress", "name": row.get("name"), "namespace": row.get("namespace"), "evidence_ids": [row["evidence_id"]], "health": "unknown", "backend_services": sorted(set(backends)), "findings": []}


def _storage_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    resource, kind = row["resource"], row["kind"]
    spec, status = _spec(resource), _status(resource)
    name, eid, stamp = row.get("name"), row["evidence_id"], row.get("timestamp")
    phase = str(status.get("phase") or "")
    findings: List[Dict[str, Any]] = []
    if kind == "persistentvolumeclaim" and phase.lower() == "pending":
        findings.append(_finding("pvc_pending", "high", "PVC is Pending", [eid], kind, name, stamp, "storage"))
    if any(token in row["text"] for token in ("failedmount", "failed mount", "unable to attach", "failedattachvolume", "mountvolume")):
        findings.append(_finding("volume_attach_mount_failure", "high", "Volume attach/mount failure observed", [eid], kind, name, stamp, "storage"))
    return {"kind": kind, "name": name, "namespace": row.get("namespace"), "evidence_ids": [eid], "health": "degraded" if findings else ("healthy" if phase.lower() in {"bound", "available"} else "unknown"), "phase": phase or None, "storage_class": spec.get("storageClassName"), "volume_name": spec.get("volumeName"), "claim_ref": spec.get("claimRef") if isinstance(spec.get("claimRef"), Mapping) else None, "findings": findings}


def _hpa_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    resource = row["resource"]
    spec, status = _spec(resource), _status(resource)
    name, eid, stamp = row.get("name"), row["evidence_id"], row.get("timestamp")
    desired, current, max_replicas = status.get("desiredReplicas"), status.get("currentReplicas"), spec.get("maxReplicas")
    findings: List[Dict[str, Any]] = []
    if desired is not None and max_replicas is not None:
        try:
            if float(desired) >= float(max_replicas):
                findings.append(_finding("hpa_at_max", "medium", "HPA desired replicas reached configured maximum", [eid], "horizontalpodautoscaler", name, stamp))
        except (TypeError, ValueError):
            pass
    conditions = _condition_map(status)
    if str(conditions.get("AbleToScale", {}).get("status") or "").lower() == "false":
        findings.append(_finding("hpa_unable_to_scale", "high", "HPA reports AbleToScale=False", [eid], "horizontalpodautoscaler", name, stamp))
    return {"kind": "horizontalpodautoscaler", "name": name, "namespace": row.get("namespace"), "evidence_ids": [eid], "health": "degraded" if findings else "healthy", "current_replicas": current, "desired_replicas": desired, "min_replicas": spec.get("minReplicas"), "max_replicas": max_replicas, "conditions": conditions, "findings": findings}


def _pdb_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    status = _status(row["resource"])
    name, eid, stamp = row.get("name"), row["evidence_id"], row.get("timestamp")
    allowed, current_healthy, desired_healthy = status.get("disruptionsAllowed"), status.get("currentHealthy"), status.get("desiredHealthy")
    findings: List[Dict[str, Any]] = []
    if allowed in (0, "0") and current_healthy is not None and desired_healthy is not None:
        findings.append(_finding("pdb_blocking_condition", "medium", "PDB currently allows zero voluntary disruptions", [eid], "poddisruptionbudget", name, stamp, None, {"current_healthy": current_healthy, "desired_healthy": desired_healthy}))
    return {"kind": "poddisruptionbudget", "name": name, "namespace": row.get("namespace"), "evidence_ids": [eid], "health": "constrained" if findings else "healthy", "disruptions_allowed": allowed, "current_healthy": current_healthy, "desired_healthy": desired_healthy, "findings": findings}


def _networkpolicy_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    spec = _spec(row["resource"])
    pod_selector = spec.get("podSelector") if isinstance(spec.get("podSelector"), Mapping) else {}
    return {"kind": "networkpolicy", "name": row.get("name"), "namespace": row.get("namespace"), "evidence_ids": [row["evidence_id"]], "health": "unknown", "pod_selector": dict(pod_selector), "policy_types": list(spec.get("policyTypes") or []), "ingress_rule_count": len(spec.get("ingress") or []), "egress_rule_count": len(spec.get("egress") or []), "findings": []}


def _metadata_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {"kind": row["kind"], "name": row.get("name"), "namespace": row.get("namespace"), "evidence_ids": [row["evidence_id"]], "health": "unknown", "metadata": _safe_metadata(row["resource"]), "data_redacted": True, "findings": []}


def _webhook_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    webhooks = row["resource"].get("webhooks") if isinstance(row["resource"].get("webhooks"), list) else []
    return {"kind": row["kind"], "name": row.get("name"), "evidence_ids": [row["evidence_id"]], "health": "unknown", "webhook_count": len(webhooks), "webhook_names": [str(w.get("name")) for w in webhooks if isinstance(w, Mapping) and w.get("name")][:20], "failure_policies": [str(w.get("failurePolicy")) for w in webhooks if isinstance(w, Mapping) and w.get("failurePolicy")][:20], "findings": []}


def _event_analyzer(row: Mapping[str, Any]) -> Dict[str, Any]:
    resource = row["resource"]
    text = row.get("text") or ""
    reason = resource.get("reason") or _status(resource).get("reason")
    involved = resource.get("involvedObject") if isinstance(resource.get("involvedObject"), Mapping) else {}
    findings: List[Dict[str, Any]] = []
    tokens = {
        "failed_admission_webhook": ("failed calling webhook", "admission webhook", "failed admission"),
        "failed_scheduling": ("failedscheduling", "failed scheduling"),
        "volume_attach_mount_failure": ("failedmount", "failedattachvolume", "unable to attach or mount"),
        "dns_failure": ("nxdomain", "server misbehaving", "temporary failure in name resolution", "dns lookup failed"),
        "network_reachability": ("networkpolicy", "connection refused", "i/o timeout", "no route to host"),
        "probe_failure": ("readiness probe failed", "liveness probe failed", "startup probe failed"),
    }
    for code, patterns in tokens.items():
        if any(pattern in text for pattern in patterns):
            handoff = "network" if code in {"dns_failure", "network_reachability"} else ("storage" if code == "volume_attach_mount_failure" else None)
            findings.append(_finding(code, "high" if code != "probe_failure" else "medium", code.replace("_", " "), [row["evidence_id"]], "event", str(involved.get("name") or row.get("name") or ""), row.get("timestamp"), handoff, {"reason": reason, "involved_kind": involved.get("kind")}))
    return {"kind": "event", "name": row.get("name"), "namespace": row.get("namespace"), "evidence_ids": [row["evidence_id"]], "health": "degraded" if findings else "unknown", "reason": reason, "involved_object": dict(involved), "findings": findings}


def _analyze_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    kind = row["kind"]
    if kind == "pod": return _pod_analyzer(row)
    if kind in {"replicaset", "deployment", "statefulset", "daemonset", "job", "cronjob"}: return _controller_analyzer(row)
    if kind == "node": return _node_analyzer(row)
    if kind == "service": return _service_analyzer(row)
    if kind in {"endpoint", "endpointslice"}: return _endpoint_analyzer(row)
    if kind == "ingress": return _ingress_analyzer(row)
    if kind in {"persistentvolumeclaim", "persistentvolume"}: return _storage_analyzer(row)
    if kind == "horizontalpodautoscaler": return _hpa_analyzer(row)
    if kind == "poddisruptionbudget": return _pdb_analyzer(row)
    if kind == "networkpolicy": return _networkpolicy_analyzer(row)
    if kind in {"configmap", "secret"}: return _metadata_analyzer(row)
    if kind in {"validatingwebhookconfiguration", "mutatingwebhookconfiguration"}: return _webhook_analyzer(row)
    if kind == "event": return _event_analyzer(row)
    return {"kind": kind, "name": row.get("name"), "namespace": row.get("namespace"), "evidence_ids": [row["evidence_id"]], "health": "unknown", "findings": []}


def _metric_features(evidence: List[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for index, item in enumerate(evidence):
        if str(item.get("type") or "").lower() != "metric":
            continue
        raw = _raw(item)
        name = str(item.get("name") or item.get("metric") or raw.get("name") or "").lower()
        value = _numeric(item.get("value") if item.get("value") is not None else raw.get("value"))
        stamp = _timestamp(item)
        row = {
            "evidence_id": _eid(item, index), "name": name, "value": value,
            "timestamp": stamp.isoformat() if stamp else None,
            "pod": item.get("pod") or raw.get("pod") or raw.get("pod_name"),
            "container": item.get("container") or raw.get("container"),
            "namespace": item.get("namespace") or raw.get("namespace"),
            "historical_p95": _numeric(raw.get("historical_p95") or raw.get("p95") or raw.get("baseline_p95")),
            "historical_p99": _numeric(raw.get("historical_p99") or raw.get("p99") or raw.get("baseline_p99")),
        }
        if "memory" in name and any(token in name for token in ("working_set", "usage", "rss")): result["memory_usage"].append(row)
        elif "cpu" in name and any(token in name for token in ("usage", "cores", "rate")) and "thrott" not in name: result["cpu_usage"].append(row)
        if "thrott" in name: result["cpu_throttling"].append(row)
        if any(token in name for token in ("dns", "coredns")) and any(token in name for token in ("error", "fail", "latency", "duration")): result["dns"].append(row)
        if any(token in name for token in ("network", "tcp", "packet")) and any(token in name for token in ("error", "drop", "timeout", "latency", "reset")): result["network"].append(row)
    return dict(result)


def _resource_config(analyses: Sequence[Mapping[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    result: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for analysis in analyses:
        if analysis.get("kind") != "pod": continue
        pod = str(analysis.get("name") or "")
        for container in analysis.get("containers") or []:
            if not isinstance(container, Mapping): continue
            cname = str(container.get("name") or "")
            requests = container.get("requests") if isinstance(container.get("requests"), Mapping) else {}
            limits = container.get("limits") if isinstance(container.get("limits"), Mapping) else {}
            result[(pod, cname)] = {"cpu_request": _cpu_quantity(requests.get("cpu")), "cpu_limit": _cpu_quantity(limits.get("cpu")), "memory_request": _bytes_quantity(requests.get("memory")), "memory_limit": _bytes_quantity(limits.get("memory"))}
    return result


def _resource_usage_comparison(analyses: Sequence[Mapping[str, Any]], metrics: Mapping[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    config = _resource_config(analyses)
    comparisons: List[Dict[str, Any]] = []
    for metric_kind in ("cpu_usage", "memory_usage"):
        for row in metrics.get(metric_kind, []):
            pod, container = str(row.get("pod") or ""), str(row.get("container") or "")
            candidates = [((p, c), cfg) for (p, c), cfg in config.items() if (not pod or p == pod) and (not container or c == container)]
            if len(candidates) != 1: continue
            (pkey, ckey), cfg = candidates[0]
            value = row.get("historical_p95")
            basis = "historical_p95"
            if value is None:
                value, basis = row.get("value"), "current"
            if value is None: continue
            is_cpu = metric_kind == "cpu_usage"
            request = cfg["cpu_request"] if is_cpu else cfg["memory_request"]
            limit = cfg["cpu_limit"] if is_cpu else cfg["memory_limit"]
            ratio_req = round(float(value) / request, 3) if request not in (None, 0) else None
            ratio_lim = round(float(value) / limit, 3) if limit not in (None, 0) else None
            recommendation = None
            if ratio_req is not None and ratio_req > 1.5:
                recommendation = f"{metric_kind} {basis} materially exceeds configured request; validate request sizing against historical demand"
            if ratio_lim is not None and ratio_lim >= 0.9:
                recommendation = f"{metric_kind} {basis} is close to configured limit; investigate throttling/OOM risk before changing limits"
            comparisons.append({"pod": pkey, "container": ckey, "metric": metric_kind, "basis": basis, "usage": value, "request": request, "limit": limit, "usage_to_request": ratio_req, "usage_to_limit": ratio_lim, "evidence_id": row.get("evidence_id"), "recommendation": recommendation})
    return comparisons


def _timeline(evidence: List[Mapping[str, Any]], analyses_by_eid: Mapping[str, Mapping[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        eid = _eid(item, index)
        stamp = _timestamp(item)
        if not stamp: continue
        analysis = analyses_by_eid.get(eid)
        signals = [f.get("code") for f in (analysis.get("findings") if isinstance(analysis, Mapping) else []) if isinstance(f, Mapping)]
        result.append({"timestamp": stamp.isoformat(), "evidence_id": eid, "type": str(item.get("type") or "").lower(), "kind": _kind(item), "signals": signals[:8], "summary": _text(item)[:180]})
    result.sort(key=lambda x: x["timestamp"])
    return result[:120]


def _timeline_correlations(timeline: Sequence[Mapping[str, Any]], window_seconds: int = 300) -> List[Dict[str, Any]]:
    rows = [(row, _parse_time(row.get("timestamp"))) for row in timeline]
    result: List[Dict[str, Any]] = []
    for i, (left, lt) in enumerate(rows):
        if not lt or left.get("type") not in {"event", "alert"}: continue
        for right, rt in rows[i + 1:]:
            if not rt: continue
            delta = (rt - lt).total_seconds()
            if delta > window_seconds: break
            if right.get("type") in {"metric", "log", "telemetry"}:
                result.append({"event_evidence_id": left.get("evidence_id"), "correlated_evidence_id": right.get("evidence_id"), "delta_seconds": delta, "event_signals": left.get("signals") or [], "correlated_type": right.get("type")})
                if len(result) >= 30: return result
    return result


def _causal_chains(analyses: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    by_kind: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for analysis in analyses: by_kind[str(analysis.get("kind") or "unknown")].append(analysis)
    pods, services = by_kind.get("pod", []), by_kind.get("service", [])
    endpoints = by_kind.get("endpoint", []) + by_kind.get("endpointslice", [])
    controllers = sum((by_kind.get(k, []) for k in ("replicaset", "deployment", "statefulset", "daemonset", "job", "cronjob")), [])
    nodes, pvcs, pvs = by_kind.get("node", []), by_kind.get("persistentvolumeclaim", []), by_kind.get("persistentvolume", [])
    policies, ingresses = by_kind.get("networkpolicy", []), by_kind.get("ingress", [])
    chains: List[Dict[str, Any]] = []
    service_names = {str(x.get("name")): x for x in services if x.get("name")}
    pod_names = {str(x.get("name")): x for x in pods if x.get("name")}
    controller_names = {str(x.get("name")): x for x in controllers if x.get("name")}
    node_names = {str(x.get("name")): x for x in nodes if x.get("name")}
    pvc_names = {str(x.get("name")): x for x in pvcs if x.get("name")}
    pv_names = {str(x.get("name")): x for x in pvs if x.get("name")}
    for service in services or [{"name": None, "selector": {}}]:
        selected_pods = [p for p in pods if _selector_matches(service.get("selector") or {}, p.get("labels") or {})]
        endpoint_refs: List[Mapping[str, Any]] = []
        for endpoint in endpoints:
            if service.get("name") and endpoint.get("name") and (endpoint.get("name") == service.get("name") or str(endpoint.get("name")).startswith(str(service.get("name")) + "-")):
                endpoint_refs.extend(x for x in endpoint.get("target_refs") or [] if isinstance(x, Mapping))
        for ref in endpoint_refs:
            if ref.get("name") in pod_names and pod_names[str(ref.get("name"))] not in selected_pods: selected_pods.append(pod_names[str(ref.get("name"))])
        if service.get("name") and endpoints and not endpoint_refs and not selected_pods:
            chains.append({"service": service.get("name"), "endpoint": None, "pod": None, "controller": None, "node": None, "storage": [], "network": [], "missing_links": ["endpoint", "pod"]})
            continue
        for pod in selected_pods:
            owner = pod.get("owner") or {}
            controller = controller_names.get(str(owner.get("name") or ""))
            if controller and controller.get("kind") == "replicaset":
                rs_owner = controller.get("owner") or {}
                controller = controller_names.get(str(rs_owner.get("name") or "")) or controller
            node = node_names.get(str(pod.get("node") or ""))
            storage: List[Dict[str, Any]] = []
            for claim in pod.get("pvc_claims") or []:
                pvc = pvc_names.get(str(claim))
                entry: Dict[str, Any] = {"pvc": claim, "pv": pvc.get("volume_name") if pvc else None}
                if pvc and pvc.get("volume_name") and pvc.get("volume_name") in pv_names: entry["pv_evidence_ids"] = pv_names[str(pvc["volume_name"])].get("evidence_ids")
                storage.append(entry)
            missing: List[str] = []
            if not pod.get("node"): missing.append("node")
            if owner and not controller: missing.append("controller")
            chains.append({"service": service.get("name"), "endpoint": "observed" if endpoint_refs else None, "pod": pod.get("name"), "controller": controller.get("name") if controller else owner.get("name"), "controller_kind": controller.get("kind") if controller else owner.get("kind"), "node": node.get("name") if node else pod.get("node"), "storage": storage, "network": [p.get("name") for p in policies if p.get("name")], "missing_links": missing})
    for ingress in ingresses:
        for backend in ingress.get("backend_services") or []:
            chains.append({"ingress": ingress.get("name"), "service": backend, "service_observed": backend in service_names, "endpoint": None, "pod": None, "controller": None, "node": None, "storage": [], "network": [], "missing_links": [] if backend in service_names else ["service"]})
    return chains[:80]


def _cross_resource_findings(analyses: Sequence[Mapping[str, Any]], metrics: Mapping[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    services = [x for x in analyses if x.get("kind") == "service"]
    endpoints = [x for x in analyses if x.get("kind") in {"endpoint", "endpointslice"}]
    for service in services:
        name = str(service.get("name") or "")
        related = [x for x in endpoints if x.get("name") == name or str(x.get("name") or "").startswith(name + "-")]
        if related and sum(int(x.get("ready_endpoints") or 0) for x in related) == 0:
            eids = list(service.get("evidence_ids") or []) + [eid for x in related for eid in x.get("evidence_ids") or []]
            findings.append(_finding("service_without_endpoint", "high", f"Service {name} has no ready endpoint", eids, "service", name))
    service_names = {str(x.get("name")) for x in services if x.get("name")}
    for ingress in [x for x in analyses if x.get("kind") == "ingress"]:
        missing = [x for x in ingress.get("backend_services") or [] if x not in service_names]
        if missing:
            findings.append(_finding("ingress_backend_mismatch", "high", f"Ingress references missing backend service(s): {', '.join(missing)}", ingress.get("evidence_ids") or [], "ingress", ingress.get("name")))
    if metrics.get("dns") and any((x.get("value") or 0) > 0 for x in metrics["dns"]):
        findings.append(_finding("dns_service_discovery_symptom", "high", "DNS/service-discovery metrics show failures or elevated latency", [x["evidence_id"] for x in metrics["dns"] if x.get("evidence_id")], "service", None, None, "network"))
    policies = [x for x in analyses if x.get("kind") == "networkpolicy"]
    if policies and metrics.get("network"):
        eids = [eid for p in policies for eid in p.get("evidence_ids") or []] + [x["evidence_id"] for x in metrics["network"] if x.get("evidence_id")]
        findings.append(_finding("networkpolicy_reachability_candidate", "medium", "NetworkPolicy exists alongside reachability symptoms; policy causation requires path validation", eids, "networkpolicy", policies[0].get("name"), None, "network"))
    return findings


def _classify_cause(findings: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    infra_codes = {"node_not_ready", "node_pressure", "node_eviction_pressure", "insufficient_resources"}
    storage_codes = {"pvc_pending", "volume_attach_mount_failure"}
    network_codes = {"dns_failure", "dns_service_discovery_symptom", "network_reachability", "networkpolicy_reachability_candidate"}
    workload_codes = {"crashloopbackoff", "oomkilled", "nonzero_exit", "readiness_probe_failure", "liveness_probe_failure", "startup_probe_failure", "rollout_stalled", "generation_mismatch", "unavailable_replicas", "replica_shortfall", "image_pull_failure", "failed_admission_webhook", "hpa_unable_to_scale"}
    codes = {str(f.get("code")) for f in findings}
    underlying: List[str] = []
    if codes & infra_codes: underlying.append("infrastructure")
    if codes & storage_codes: underlying.append("storage")
    if codes & network_codes: underlying.append("network")
    if codes & workload_codes: underlying.append("kubernetes_workload")
    return {"kubernetes_symptom_present": bool(codes & workload_codes), "underlying_domains": underlying, "policy": "prefer_underlying_domain_handoff_when_live_evidence_is_stronger_than_workload_symptom"}


def _gaps(analyses: Sequence[Mapping[str, Any]], findings: Sequence[Mapping[str, Any]], metrics: Mapping[str, List[Dict[str, Any]]], chains: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    kinds = {str(x.get("kind")) for x in analyses}
    gaps: List[Dict[str, Any]] = []
    if "pod" in kinds and "event" not in kinds: gaps.append({"evidence": "Kubernetes Events for affected workload", "reason": "event chronology helps distinguish state from cause", "information_gain": 0.9})
    if "pod" in kinds and not metrics.get("cpu_usage") and not metrics.get("memory_usage"): gaps.append({"evidence": "historical Prometheus CPU/memory usage for affected pod/container", "reason": "required to explain request/limit sizing and resource pressure", "information_gain": 0.85})
    if any(f.get("code") in {"pvc_pending", "volume_attach_mount_failure"} for f in findings) and "persistentvolume" not in kinds: gaps.append({"evidence": "PV/storage backend state and attach/mount events", "reason": "separate Kubernetes storage symptom from backend storage cause", "information_gain": 0.95})
    if any(f.get("code") in {"node_pressure", "node_not_ready", "failed_scheduling"} for f in findings): gaps.append({"evidence": "node infrastructure metrics and kubelet/system logs", "reason": "validate underlying node pressure outside Kubernetes object state", "information_gain": 0.93})
    if any(f.get("code") in {"dns_failure", "dns_service_discovery_symptom"} for f in findings): gaps.append({"evidence": "CoreDNS logs/metrics plus source-to-service DNS test evidence", "reason": "separate DNS resolver failure from service endpoint/network policy failure", "information_gain": 0.94})
    if any(chain.get("missing_links") for chain in chains): gaps.append({"evidence": "missing Service/Endpoint/Pod/Controller/Node topology links", "reason": "complete causal chain before attributing root cause", "information_gain": 0.88})
    return sorted(gaps, key=lambda x: -float(x["information_gain"]))[:10]


def build_kubernetes_analysis(evidence: List[Mapping[str, Any]], *, service_name: Optional[str] = None, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    context = context or {}
    rows: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        kind = _kind(item)
        if kind != "unknown" and (kind in SUPPORTED_KINDS or str(item.get("type") or "").lower() in {"event", "alert"}):
            rows.append(_row_base(item, index))
    analyses = [_analyze_row(row) for row in rows]
    analyses_by_eid = {str(a["evidence_ids"][0]): a for a in analyses if a.get("evidence_ids")}
    metrics = _metric_features(evidence)
    chains = _causal_chains(analyses)
    findings = [f for analysis in analyses for f in analysis.get("findings") or [] if isinstance(f, Mapping)]
    findings.extend(_cross_resource_findings(analyses, metrics))
    comparisons = _resource_usage_comparison(analyses, metrics)
    for row in comparisons:
        if row.get("recommendation"):
            findings.append(_finding("request_limit_mismatch", "medium", str(row["recommendation"]), [str(row.get("evidence_id") or "")], "pod", row.get("pod"), None, None, {k: row.get(k) for k in ("container", "metric", "basis", "usage", "request", "limit", "usage_to_request", "usage_to_limit")}))
    for throttle in metrics.get("cpu_throttling", []):
        if (throttle.get("value") or 0) > 0:
            findings.append(_finding("cpu_throttling", "medium", "Container CPU throttling is present", [str(throttle.get("evidence_id") or "")], "pod", str(throttle.get("pod") or "") or None))
    for index, item in enumerate(evidence):
        text = _text(item).lower()
        stamp = _timestamp(item)
        stamp_value = stamp.isoformat() if stamp else None
        if "failed calling webhook" in text or ("admission webhook" in text and any(x in text for x in ("failed", "timeout", "denied"))):
            findings.append(_finding("failed_admission_webhook", "high", "Admission webhook failure/denial observed", [_eid(item, index)], "admission_webhook", None, stamp_value))
        if any(token in text for token in ("nxdomain", "dns lookup failed", "temporary failure in name resolution")):
            findings.append(_finding("dns_failure", "high", "DNS resolution failure observed", [_eid(item, index)], "service", service_name, stamp_value, "network"))
    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for finding in findings:
        key = (str(finding.get("code")), str(finding.get("resource_kind")), str(finding.get("resource_name") or ""))
        if key not in merged: merged[key] = dict(finding)
        else:
            merged[key]["evidence_ids"] = list(dict.fromkeys((merged[key].get("evidence_ids") or []) + (finding.get("evidence_ids") or [])))
            if not merged[key].get("anomaly_start") and finding.get("anomaly_start"): merged[key]["anomaly_start"] = finding.get("anomaly_start")
    findings = list(merged.values())
    timeline = _timeline(evidence, analyses_by_eid)
    cause = _classify_cause(findings)
    handoffs: List[str] = []
    for finding in findings:
        target = finding.get("handoff")
        if target and target not in {"kubernetes", "kubernetes_workload"} and target not in handoffs: handoffs.append(str(target))
    for target in cause["underlying_domains"]:
        if target != "kubernetes_workload" and target not in handoffs: handoffs.append(target)
    counts: Dict[str, int] = defaultdict(int)
    for analysis in analyses: counts[str(analysis.get("kind") or "unknown")] += 1
    gaps = _gaps(analyses, findings, metrics, chains)
    return {
        "policy": "deterministic_resource_analyzers_are_observations_not_root_cause; synthesis_requires_live_evidence_and_timeline_correlation",
        "service_name": service_name, "supported_resource_kinds": list(SUPPORTED_KINDS),
        "resource_counts": dict(sorted(counts.items())), "resource_analyses": analyses,
        "findings": findings[:80], "unhealthy_resource_count": sum(1 for a in analyses if a.get("health") in {"degraded", "constrained"}),
        "causal_chains": chains, "event_timeline": timeline, "timeline_correlations": _timeline_correlations(timeline),
        "metric_features": metrics, "resource_usage_comparison": comparisons,
        "kubernetes_vs_infrastructure": cause, "handoff_candidates": handoffs[:6],
        "evidence_gaps": gaps, "next_best_evidence": gaps[:6],
        "secret_metadata_safety": {"secret_payload_exposed": False, "secret_objects": sum(1 for a in analyses if a.get("kind") == "secret"), "policy": "Secret and ConfigMap payload values are never projected into deterministic analysis; metadata only"},
        "execution_boundary": "analysis_only; no kubectl apply/delete/rollout restart/scale",
    }
