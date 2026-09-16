from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple


Analyzer = Callable[[Mapping[str, Any], str], Dict[str, Any]]


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _resource(item: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = _raw(item)
    for value in (item.get("resource"), item.get("object"), raw.get("resource"), raw.get("object"), raw):
        if isinstance(value, Mapping) and value.get("kind"):
            return value
    return {}


def _kind(resource: Mapping[str, Any]) -> str:
    normalized = "".join(ch for ch in str(resource.get("kind") or "").lower() if ch.isalpha())
    return {
        "endpoints": "endpoint",
        "pvc": "persistentvolumeclaim",
        "pv": "persistentvolume",
        "hpa": "horizontalpodautoscaler",
        "pdb": "poddisruptionbudget",
    }.get(normalized, normalized)


def _metadata(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("metadata")
    return value if isinstance(value, Mapping) else {}


def _spec(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("spec")
    return value if isinstance(value, Mapping) else {}


def _status(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("status")
    return value if isinstance(value, Mapping) else {}


def _conditions(resource: Mapping[str, Any]) -> List[Dict[str, Any]]:
    value = _status(resource).get("conditions")
    if not isinstance(value, list):
        return []
    rows: List[Dict[str, Any]] = []
    for condition in value:
        if not isinstance(condition, Mapping):
            continue
        rows.append({
            "type": condition.get("type"),
            "status": condition.get("status"),
            "reason": condition.get("reason"),
            "message": str(condition.get("message") or "")[:240] or None,
            "last_transition_time": condition.get("lastTransitionTime"),
        })
    return rows


def _base(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    meta = _metadata(resource)
    return {
        "kind": _kind(resource),
        "name": meta.get("name"),
        "namespace": meta.get("namespace"),
        "evidence_ids": [evidence_id],
        "findings": [],
    }


def _finding(code: str, severity: str, message: str, evidence_id: str, *, handoff: Optional[str] = None, details: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "evidence_ids": [evidence_id],
        "handoff": handoff,
        "details": dict(details or {}),
    }


def _replica_state(resource: Mapping[str, Any]) -> Dict[str, Any]:
    spec, status = _spec(resource), _status(resource)
    return {
        "desired": spec.get("replicas"),
        "current": status.get("replicas") or status.get("currentReplicas"),
        "ready": status.get("readyReplicas"),
        "available": status.get("availableReplicas"),
        "unavailable": status.get("unavailableReplicas"),
        "updated": status.get("updatedReplicas"),
    }


def analyze_pod(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec, status = _spec(resource), _status(resource)
    statuses = [x for x in status.get("containerStatuses") or [] if isinstance(x, Mapping)]
    row.update({
        "phase": status.get("phase"),
        "node": spec.get("nodeName"),
        "conditions": _conditions(resource),
        "restart_count": sum(int(x.get("restartCount") or 0) for x in statuses),
        "container_states": [{"name": x.get("name"), "ready": x.get("ready"), "restart_count": x.get("restartCount"), "state_keys": sorted((x.get("state") or {}).keys()) if isinstance(x.get("state"), Mapping) else []} for x in statuses[:20]],
    })
    return row


def analyze_replicaset(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    row.update(_replica_state(resource))
    row["conditions"] = _conditions(resource)
    return row


def analyze_deployment(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    row.update(_replica_state(resource))
    meta, status = _metadata(resource), _status(resource)
    row.update({"generation": meta.get("generation"), "observed_generation": status.get("observedGeneration"), "conditions": _conditions(resource)})
    return row


def analyze_statefulset(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    row.update(_replica_state(resource))
    status = _status(resource)
    row.update({"current_revision": status.get("currentRevision"), "update_revision": status.get("updateRevision"), "current_replicas": status.get("currentReplicas"), "conditions": _conditions(resource)})
    if status.get("currentRevision") and status.get("updateRevision") and status.get("currentRevision") != status.get("updateRevision"):
        row["findings"].append(_finding("statefulset_revision_mismatch", "medium", "StatefulSet current and update revisions differ", evidence_id, handoff="change"))
    return row


def analyze_daemonset(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    status = _status(resource)
    desired = status.get("desiredNumberScheduled")
    ready = status.get("numberReady")
    unavailable = status.get("numberUnavailable")
    misscheduled = status.get("numberMisscheduled")
    row.update({
        "desired_scheduled": desired,
        "current_scheduled": status.get("currentNumberScheduled"),
        "ready": ready,
        "available": status.get("numberAvailable"),
        "unavailable": unavailable,
        "misscheduled": misscheduled,
        "updated_scheduled": status.get("updatedNumberScheduled"),
        "conditions": _conditions(resource),
    })
    if unavailable not in (None, 0, "0"):
        row["findings"].append(_finding("daemonset_unavailable", "high", "DaemonSet has unavailable scheduled pods", evidence_id, details={"desired": desired, "ready": ready, "unavailable": unavailable}))
    if misscheduled not in (None, 0, "0"):
        row["findings"].append(_finding("daemonset_misscheduled", "medium", "DaemonSet reports misscheduled pods", evidence_id, details={"misscheduled": misscheduled}))
    return row


def analyze_job(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    status = _status(resource)
    row.update({"active": status.get("active"), "succeeded": status.get("succeeded"), "failed": status.get("failed"), "completion_time": status.get("completionTime"), "conditions": _conditions(resource)})
    if status.get("failed"):
        row["findings"].append(_finding("job_failed", "high", "Job reports failed pod executions", evidence_id, details={"failed": status.get("failed")}))
    for condition in row["conditions"]:
        if str(condition.get("type") or "").lower() == "failed" and str(condition.get("status") or "").lower() == "true":
            row["findings"].append(_finding("job_failed_condition", "high", "Job condition Failed=True", evidence_id, details={"reason": condition.get("reason")}))
    return row


def analyze_cronjob(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec, status = _spec(resource), _status(resource)
    active = status.get("active") if isinstance(status.get("active"), list) else []
    row.update({
        "schedule": spec.get("schedule"),
        "suspend": spec.get("suspend"),
        "concurrency_policy": spec.get("concurrencyPolicy"),
        "active_jobs": [x.get("name") for x in active if isinstance(x, Mapping) and x.get("name")],
        "last_schedule_time": status.get("lastScheduleTime"),
        "last_successful_time": status.get("lastSuccessfulTime"),
    })
    return row


def analyze_node(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    row.update({"unschedulable": bool(_spec(resource).get("unschedulable")), "conditions": _conditions(resource)})
    return row


def analyze_service(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec = _spec(resource)
    selector = spec.get("selector") if isinstance(spec.get("selector"), Mapping) else {}
    row.update({"type": spec.get("type"), "selector": dict(selector), "cluster_ip": spec.get("clusterIP"), "ports": [dict(x) for x in spec.get("ports") or [] if isinstance(x, Mapping)][:20]})
    return row


def _endpoint_counts(resource: Mapping[str, Any]) -> Tuple[int, int]:
    kind = _kind(resource)
    ready = total = 0
    if kind == "endpointslice":
        for endpoint in resource.get("endpoints") or []:
            if not isinstance(endpoint, Mapping):
                continue
            total += 1
            conditions = endpoint.get("conditions") if isinstance(endpoint.get("conditions"), Mapping) else {}
            if conditions.get("ready") is not False:
                ready += 1
    else:
        for subset in resource.get("subsets") or []:
            if not isinstance(subset, Mapping):
                continue
            ready += len([x for x in subset.get("addresses") or [] if isinstance(x, Mapping)])
            total += len([x for x in subset.get("addresses") or [] if isinstance(x, Mapping)])
            total += len([x for x in subset.get("notReadyAddresses") or [] if isinstance(x, Mapping)])
    return ready, total


def analyze_endpoint(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    ready, total = _endpoint_counts(resource)
    row.update({"ready_endpoints": ready, "total_endpoints": total})
    return row


def analyze_endpointslice(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    return analyze_endpoint(resource, evidence_id)


def analyze_ingress(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec = _spec(resource)
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
    row.update({"ingress_class": spec.get("ingressClassName"), "backend_services": sorted(set(backends)), "load_balancer": _status(resource).get("loadBalancer")})
    return row


def analyze_pvc(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec, status = _spec(resource), _status(resource)
    row.update({"phase": status.get("phase"), "storage_class": spec.get("storageClassName"), "volume_name": spec.get("volumeName"), "access_modes": list(spec.get("accessModes") or []), "conditions": _conditions(resource)})
    return row


def analyze_pv(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec, status = _spec(resource), _status(resource)
    claim = spec.get("claimRef") if isinstance(spec.get("claimRef"), Mapping) else {}
    row.update({"phase": status.get("phase"), "storage_class": spec.get("storageClassName"), "claim_ref": {"name": claim.get("name"), "namespace": claim.get("namespace")}, "access_modes": list(spec.get("accessModes") or [])})
    return row


def analyze_hpa(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec, status = _spec(resource), _status(resource)
    row.update({"min_replicas": spec.get("minReplicas"), "max_replicas": spec.get("maxReplicas"), "current_replicas": status.get("currentReplicas"), "desired_replicas": status.get("desiredReplicas"), "current_metrics": status.get("currentMetrics"), "conditions": _conditions(resource)})
    for condition in row["conditions"]:
        if str(condition.get("type") or "").lower() == "scalinglimited" and str(condition.get("status") or "").lower() == "true":
            row["findings"].append(_finding("hpa_scaling_limited", "medium", "HPA reports ScalingLimited=True", evidence_id, details={"reason": condition.get("reason")}))
    return row


def analyze_pdb(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    status = _status(resource)
    row.update({"disruptions_allowed": status.get("disruptionsAllowed"), "current_healthy": status.get("currentHealthy"), "desired_healthy": status.get("desiredHealthy"), "expected_pods": status.get("expectedPods"), "conditions": _conditions(resource)})
    if status.get("disruptionsAllowed") in (0, "0"):
        row["findings"].append(_finding("pdb_blocking_condition", "medium", "PDB currently permits zero voluntary disruptions", evidence_id))
    return row


def analyze_networkpolicy(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    spec = _spec(resource)
    row.update({"pod_selector": spec.get("podSelector") if isinstance(spec.get("podSelector"), Mapping) else {}, "policy_types": list(spec.get("policyTypes") or []), "ingress_rule_count": len(spec.get("ingress") or []), "egress_rule_count": len(spec.get("egress") or [])})
    return row


def _metadata_only(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    meta = _metadata(resource)
    annotations = meta.get("annotations") if isinstance(meta.get("annotations"), Mapping) else {}
    row.update({"metadata": {"uid": meta.get("uid"), "generation": meta.get("generation"), "resource_version": meta.get("resourceVersion"), "label_keys": sorted(str(x) for x in (meta.get("labels") or {}).keys())[:40] if isinstance(meta.get("labels"), Mapping) else [], "annotation_keys": sorted(str(x) for x in annotations.keys())[:40]}, "payload_redacted": True})
    return row


def analyze_configmap(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    return _metadata_only(resource, evidence_id)


def analyze_secret(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    return _metadata_only(resource, evidence_id)


def _webhook(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    webhooks = [x for x in resource.get("webhooks") or [] if isinstance(x, Mapping)]
    row.update({"webhooks": [{"name": x.get("name"), "failure_policy": x.get("failurePolicy"), "timeout_seconds": x.get("timeoutSeconds"), "side_effects": x.get("sideEffects")} for x in webhooks[:30]]})
    return row


def analyze_validatingwebhook(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    return _webhook(resource, evidence_id)


def analyze_mutatingwebhook(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    return _webhook(resource, evidence_id)


def analyze_event(resource: Mapping[str, Any], evidence_id: str) -> Dict[str, Any]:
    row = _base(resource, evidence_id)
    involved = resource.get("involvedObject") if isinstance(resource.get("involvedObject"), Mapping) else {}
    row.update({"event_type": resource.get("type"), "reason": resource.get("reason"), "message": str(resource.get("message") or "")[:300] or None, "involved_object": {"kind": involved.get("kind"), "name": involved.get("name"), "namespace": involved.get("namespace")}, "count": resource.get("count"), "first_timestamp": resource.get("firstTimestamp"), "last_timestamp": resource.get("lastTimestamp")})
    return row


ANALYZERS: Dict[str, Analyzer] = {
    "pod": analyze_pod,
    "replicaset": analyze_replicaset,
    "deployment": analyze_deployment,
    "statefulset": analyze_statefulset,
    "daemonset": analyze_daemonset,
    "job": analyze_job,
    "cronjob": analyze_cronjob,
    "node": analyze_node,
    "service": analyze_service,
    "endpoint": analyze_endpoint,
    "endpointslice": analyze_endpointslice,
    "ingress": analyze_ingress,
    "persistentvolumeclaim": analyze_pvc,
    "persistentvolume": analyze_pv,
    "horizontalpodautoscaler": analyze_hpa,
    "poddisruptionbudget": analyze_pdb,
    "networkpolicy": analyze_networkpolicy,
    "configmap": analyze_configmap,
    "secret": analyze_secret,
    "validatingwebhookconfiguration": analyze_validatingwebhook,
    "mutatingwebhookconfiguration": analyze_mutatingwebhook,
    "event": analyze_event,
}


def analyze_resource_evidence(evidence: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    outputs: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        if not isinstance(item, Mapping):
            continue
        resource = _resource(item)
        if not resource:
            continue
        kind = _kind(resource)
        analyzer = ANALYZERS.get(kind)
        if analyzer is None:
            continue
        evidence_id = str(item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id") or f"anonymous:{index}")
        outputs.append(analyzer(resource, evidence_id))
    return outputs
