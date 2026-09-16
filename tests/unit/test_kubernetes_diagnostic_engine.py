import json

import pytest

from agents.kubernetes import KubernetesAgent
from agents.kubernetes.engine import build_kubernetes_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def obj(evidence_id, kind, name, *, spec=None, status=None, metadata=None, timestamp=None, **extra):
    meta = {"name": name, "namespace": "prod"}
    meta.update(metadata or {})
    resource = {"apiVersion": "v1", "kind": kind, "metadata": meta}
    if spec is not None:
        resource["spec"] = spec
    if status is not None:
        resource["status"] = status
    resource.update(extra)
    item = {"id": evidence_id, "type": "event", "source": "kubernetes", "raw_data": resource}
    if timestamp:
        item["timestamp"] = timestamp
    return item


def event(evidence_id, message, timestamp=None, reason=None, involved_kind="Pod", involved_name="payments-abc"):
    raw = {
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {"name": evidence_id, "namespace": "prod"},
        "reason": reason,
        "message": message,
        "involvedObject": {"kind": involved_kind, "name": involved_name, "namespace": "prod"},
    }
    item = {"id": evidence_id, "type": "event", "source": "kubernetes", "message": message, "raw_data": raw}
    if timestamp:
        item["timestamp"] = timestamp
    return item


def metric(evidence_id, name, value, *, pod=None, container=None, timestamp=None, **raw):
    payload = dict(raw)
    if pod is not None:
        payload["pod"] = pod
    if container is not None:
        payload["container"] = container
    item = {"id": evidence_id, "type": "metric", "source": "prometheus", "name": name, "value": value, "raw_data": payload}
    if timestamp:
        item["timestamp"] = timestamp
    return item


def codes(result):
    return {row["code"] for row in result["findings"]}


def test_crashloopbackoff_analyzer_uses_container_state_and_restart_trend():
    result = build_kubernetes_analysis([
        obj("pod", "Pod", "payments-abc", status={
            "phase": "Running",
            "containerStatuses": [{
                "name": "payments", "restartCount": 7,
                "state": {"waiting": {"reason": "CrashLoopBackOff"}},
            }],
        }),
    ], service_name="payments")

    assert "crashloopbackoff" in codes(result)
    assert "restart_trend" in codes(result)
    pod = next(row for row in result["resource_analyses"] if row["kind"] == "pod")
    assert pod["restart_count"] == 7
    assert pod["health"] == "degraded"


def test_oomkill_analyzer_preserves_exit_code_and_memory_limit_comparison():
    result = build_kubernetes_analysis([
        obj("pod", "Pod", "payments-abc", spec={
            "containers": [{
                "name": "payments",
                "resources": {"requests": {"memory": "256Mi"}, "limits": {"memory": "512Mi"}},
            }],
        }, status={
            "phase": "Running",
            "containerStatuses": [{
                "name": "payments", "restartCount": 3,
                "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}},
            }],
        }),
        metric("mem", "container_memory_working_set_bytes", 500 * 1024**2,
               pod="payments-abc", container="payments", historical_p95=500 * 1024**2),
    ], service_name="payments")

    oom = next(row for row in result["findings"] if row["code"] == "oomkilled")
    assert oom["details"]["exit_code"] == 137
    comparison = result["resource_usage_comparison"][0]
    assert comparison["basis"] == "historical_p95"
    assert comparison["usage_to_limit"] > 0.9
    assert "configured limit" in comparison["recommendation"]


def test_bad_probe_event_is_correlated_with_following_metric():
    result = build_kubernetes_analysis([
        event("probe", "Readiness probe failed: HTTP probe failed with statuscode: 500", "2026-09-16T10:00:00Z"),
        metric("err", "http_5xx_rate", 0.4, timestamp="2026-09-16T10:01:00Z"),
    ], service_name="payments")

    assert "probe_failure" in codes(result)
    assert result["timeline_correlations"]
    assert result["timeline_correlations"][0]["event_evidence_id"] == "probe"
    assert result["timeline_correlations"][0]["correlated_evidence_id"] == "err"


def test_pending_pvc_routes_to_storage_and_does_not_call_it_workload_root_cause():
    result = build_kubernetes_analysis([
        obj("pvc", "PersistentVolumeClaim", "payments-data", status={"phase": "Pending"}),
        event("mount", "FailedMount: unable to attach or mount volumes", reason="FailedMount"),
    ], service_name="payments")

    assert "pvc_pending" in codes(result)
    assert "volume_attach_mount_failure" in codes(result)
    assert "storage" in result["handoff_candidates"]
    assert "storage" in result["kubernetes_vs_infrastructure"]["underlying_domains"]


def test_failed_scheduling_detects_insufficient_resources_affinity_and_taint_context():
    result = build_kubernetes_analysis([
        event("schedule", "FailedScheduling: 0/3 nodes are available: 2 Insufficient cpu, 1 node(s) had untolerated taint and node affinity conflict", reason="FailedScheduling"),
    ], service_name="payments")

    assert "failed_scheduling" in codes(result)
    # Event-only scheduling still requests node evidence instead of claiming a node failure.
    assert any("node infrastructure" in row["evidence"] for row in result["evidence_gaps"])


def test_rollout_regression_detects_generation_lag_unavailable_replicas_and_progress_deadline():
    result = build_kubernetes_analysis([
        obj("deploy", "Deployment", "payments", metadata={"generation": 9}, spec={"replicas": 4}, status={
            "observedGeneration": 8,
            "replicas": 4,
            "readyReplicas": 2,
            "availableReplicas": 2,
            "unavailableReplicas": 2,
            "conditions": [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}],
        }),
    ], service_name="payments")

    found = codes(result)
    assert {"generation_mismatch", "unavailable_replicas", "replica_shortfall", "rollout_stalled"}.issubset(found)
    assert "change" in result["handoff_candidates"]


def test_service_without_endpoint_is_explicit_cross_resource_finding():
    result = build_kubernetes_analysis([
        obj("svc", "Service", "payments", spec={"selector": {"app": "payments"}, "ports": [{"port": 80}]}),
        obj("eps", "EndpointSlice", "payments", endpoints=[{"conditions": {"ready": False}}]),
    ], service_name="payments")

    assert "service_without_endpoint" in codes(result)
    finding = next(row for row in result["findings"] if row["code"] == "service_without_endpoint")
    assert set(finding["evidence_ids"]) == {"svc", "eps"}


def test_node_pressure_is_underlying_infrastructure_not_kubernetes_workload_cause():
    result = build_kubernetes_analysis([
        obj("node", "Node", "node-a", status={"conditions": [
            {"type": "Ready", "status": "True"},
            {"type": "MemoryPressure", "status": "True", "reason": "KubeletHasInsufficientMemory"},
        ]}),
    ], service_name="payments")

    assert "node_pressure" in codes(result)
    assert "infrastructure" in result["handoff_candidates"]
    assert result["kubernetes_vs_infrastructure"]["underlying_domains"] == ["infrastructure"]


def test_dns_failure_routes_to_network_and_requests_coredns_evidence():
    result = build_kubernetes_analysis([
        {"id": "dns-log", "type": "log", "source": "kubernetes", "message": "lookup payments.prod.svc: NXDOMAIN"},
        metric("dns-metric", "coredns_dns_request_failures_total", 8),
    ], service_name="payments")

    assert "dns_failure" in codes(result)
    assert "dns_service_discovery_symptom" in codes(result)
    assert "network" in result["handoff_candidates"]
    assert any("CoreDNS" in row["evidence"] for row in result["next_best_evidence"])


def test_healthy_deployment_remains_healthy_without_invented_failure():
    result = build_kubernetes_analysis([
        obj("deploy", "Deployment", "payments", metadata={"generation": 4}, spec={"replicas": 3, "selector": {"matchLabels": {"app": "payments"}}}, status={
            "observedGeneration": 4, "replicas": 3, "readyReplicas": 3, "availableReplicas": 3, "unavailableReplicas": 0,
        }),
        obj("pod", "Pod", "payments-abc", metadata={"labels": {"app": "payments"}, "ownerReferences": [{"kind": "Deployment", "name": "payments"}]}, spec={"nodeName": "node-a", "containers": [{"name": "payments"}]}, status={
            "phase": "Running", "conditions": [{"type": "Ready", "status": "True"}], "containerStatuses": [{"name": "payments", "restartCount": 0, "state": {"running": {}}}],
        }),
        obj("node", "Node", "node-a", status={"conditions": [{"type": "Ready", "status": "True"}]}),
    ], service_name="payments")

    assert result["unhealthy_resource_count"] == 0
    assert not result["findings"]
    assert result["kubernetes_vs_infrastructure"]["underlying_domains"] == []


def test_causal_chain_links_service_endpoint_pod_controller_node_and_storage():
    result = build_kubernetes_analysis([
        obj("svc", "Service", "payments", spec={"selector": {"app": "payments"}}),
        obj("eps", "EndpointSlice", "payments", endpoints=[{"conditions": {"ready": True}, "targetRef": {"kind": "Pod", "name": "payments-abc"}}]),
        obj("pod", "Pod", "payments-abc", metadata={"labels": {"app": "payments"}, "ownerReferences": [{"kind": "ReplicaSet", "name": "payments-rs"}]}, spec={"nodeName": "node-a", "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "payments-data"}}], "containers": [{"name": "payments"}]}, status={"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}),
        obj("rs", "ReplicaSet", "payments-rs", metadata={"ownerReferences": [{"kind": "Deployment", "name": "payments"}]}, spec={"replicas": 1}, status={"readyReplicas": 1, "availableReplicas": 1}),
        obj("deploy", "Deployment", "payments", spec={"replicas": 1}, status={"readyReplicas": 1, "availableReplicas": 1}),
        obj("node", "Node", "node-a", status={"conditions": [{"type": "Ready", "status": "True"}]}),
        obj("pvc", "PersistentVolumeClaim", "payments-data", spec={"volumeName": "pv-data"}, status={"phase": "Bound"}),
        obj("pv", "PersistentVolume", "pv-data", status={"phase": "Bound"}),
    ], service_name="payments")

    chain = next(row for row in result["causal_chains"] if row.get("pod") == "payments-abc")
    assert chain["service"] == "payments"
    assert chain["endpoint"] == "observed"
    assert chain["controller"] == "payments"
    assert chain["controller_kind"] == "deployment"
    assert chain["node"] == "node-a"
    assert chain["storage"] == [{"pvc": "payments-data", "pv": "pv-data", "pv_evidence_ids": ["pv"]}]


def test_secret_and_configmap_analyzers_never_return_payload_values():
    result = build_kubernetes_analysis([
        obj("secret", "Secret", "db-secret", data={"password": "TOP-SECRET-VALUE"}, stringData={"token": "TOKEN-VALUE"}),
        obj("cm", "ConfigMap", "app-config", data={"password": "ALSO-SENSITIVE", "mode": "prod"}),
    ])

    rendered = json.dumps(result)
    assert "TOP-SECRET-VALUE" not in rendered
    assert "TOKEN-VALUE" not in rendered
    assert "ALSO-SENSITIVE" not in rendered
    assert result["secret_metadata_safety"]["secret_payload_exposed"] is False
    assert all(row.get("data_redacted") for row in result["resource_analyses"])


class StaticKubernetesLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "static-kubernetes"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["workload requires diagnosis"],
            "workload_signals": ["CrashLoopBackOff"],
            "rollout_signals": [],
            "scheduling_signals": [],
            "network_signals": [],
            "resource_signals": [],
            "affected_components": ["payments-abc"],
            "blast_radius": "single workload",
            "hypotheses": [{
                "hypothesis": "container startup failure",
                "probability": 0.8,
                "evidence_ids": ["pod"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["inspect previous container logs"],
                "impacted_components": ["payments-abc"],
                "recommended_next_evidence": ["previous container logs"],
            }],
            "missing_evidence": [],
            "handoff_agents": [],
            "immediate_checks": ["kubectl rollout restart deployment/payments"],
            "confidence": 0.8,
        }
        return LLMResponse(content=json.dumps(payload), model="static-kubernetes")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_agent_exposes_structured_diagnostics_and_cannot_execute_rollout_restart():
    incident = AgentInput(
        incident_id="k8s-diagnostic-1",
        service_name="payments",
        evidence_summary="payments pod is restarting",
        context={"evidence": [obj("pod", "Pod", "payments-abc", status={
            "phase": "Running",
            "containerStatuses": [{"name": "payments", "restartCount": 5, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}],
        })]},
    )
    result = await KubernetesAgent(StaticKubernetesLLM()).analyze(incident)

    assert result.analysis_details["resource_analyses"]
    assert result.analysis_details["kubernetes_deterministic_analysis"]["execution_boundary"].startswith("analysis_only")
    assert result.analysis_details["execution_boundary"] == "analysis_only"
    action = result.recommended_actions[0]
    assert action.read_only is False
    assert action.requires_approval is True
    assert action.suggested_tool is None
