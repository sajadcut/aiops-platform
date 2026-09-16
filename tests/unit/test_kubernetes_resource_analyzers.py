import json

from agents.kubernetes.diagnostics import build_kubernetes_analysis
from agents.kubernetes.resource_analyzers import ANALYZERS, analyze_resource_evidence


def obj(evidence_id, kind, name, *, spec=None, status=None, metadata=None, **extra):
    meta = {"name": name, "namespace": "prod"}
    meta.update(metadata or {})
    resource = {"apiVersion": "v1", "kind": kind, "metadata": meta}
    if spec is not None:
        resource["spec"] = spec
    if status is not None:
        resource["status"] = status
    resource.update(extra)
    return {"id": evidence_id, "type": "event", "source": "kubernetes", "raw_data": resource}


def output_for(outputs, kind):
    return next(row for row in outputs if row["kind"] == kind)


def test_registry_contains_every_requested_resource_analyzer():
    expected = {
        "pod", "replicaset", "deployment", "statefulset", "daemonset", "job", "cronjob",
        "node", "service", "endpoint", "endpointslice", "ingress", "persistentvolumeclaim",
        "persistentvolume", "horizontalpodautoscaler", "poddisruptionbudget", "networkpolicy",
        "configmap", "secret", "validatingwebhookconfiguration", "mutatingwebhookconfiguration", "event",
    }
    assert expected.issubset(set(ANALYZERS))
    assert all(callable(ANALYZERS[kind]) for kind in expected)


def test_daemonset_analyzer_has_daemonset_specific_health_signals():
    outputs = analyze_resource_evidence([
        obj("ds", "DaemonSet", "node-agent", status={
            "desiredNumberScheduled": 5,
            "currentNumberScheduled": 5,
            "numberReady": 3,
            "numberAvailable": 3,
            "numberUnavailable": 2,
            "numberMisscheduled": 1,
            "updatedNumberScheduled": 4,
        }),
    ])
    row = output_for(outputs, "daemonset")
    assert row["desired_scheduled"] == 5
    assert row["ready"] == 3
    assert {x["code"] for x in row["findings"]} == {"daemonset_unavailable", "daemonset_misscheduled"}


def test_job_and_cronjob_analyzers_are_structured_independently():
    outputs = analyze_resource_evidence([
        obj("job", "Job", "migration", status={
            "active": 0,
            "succeeded": 0,
            "failed": 2,
            "conditions": [{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}],
        }),
        obj("cron", "CronJob", "cleanup", spec={
            "schedule": "*/5 * * * *",
            "suspend": False,
            "concurrencyPolicy": "Forbid",
        }, status={
            "active": [{"name": "cleanup-123"}],
            "lastScheduleTime": "2026-09-16T10:00:00Z",
            "lastSuccessfulTime": "2026-09-16T09:55:00Z",
        }),
    ])
    job = output_for(outputs, "job")
    cron = output_for(outputs, "cronjob")
    assert {x["code"] for x in job["findings"]} == {"job_failed", "job_failed_condition"}
    assert cron["schedule"] == "*/5 * * * *"
    assert cron["concurrency_policy"] == "Forbid"
    assert cron["active_jobs"] == ["cleanup-123"]


def test_statefulset_hpa_and_pdb_have_resource_specific_semantics():
    outputs = analyze_resource_evidence([
        obj("sts", "StatefulSet", "db", status={"currentRevision": "r1", "updateRevision": "r2", "readyReplicas": 2}),
        obj("hpa", "HorizontalPodAutoscaler", "api", spec={"minReplicas": 2, "maxReplicas": 10}, status={
            "currentReplicas": 10,
            "desiredReplicas": 10,
            "conditions": [{"type": "ScalingLimited", "status": "True", "reason": "TooManyReplicas"}],
        }),
        obj("pdb", "PodDisruptionBudget", "api-pdb", status={
            "disruptionsAllowed": 0,
            "currentHealthy": 2,
            "desiredHealthy": 2,
            "expectedPods": 2,
        }),
    ])
    sts = output_for(outputs, "statefulset")
    hpa = output_for(outputs, "horizontalpodautoscaler")
    pdb = output_for(outputs, "poddisruptionbudget")
    assert sts["current_revision"] == "r1" and sts["update_revision"] == "r2"
    assert sts["findings"][0]["code"] == "statefulset_revision_mismatch"
    assert hpa["desired_replicas"] == 10
    assert hpa["findings"][0]["code"] == "hpa_scaling_limited"
    assert pdb["disruptions_allowed"] == 0
    assert pdb["findings"][0]["code"] == "pdb_blocking_condition"


def test_admission_webhook_analyzers_expose_metadata_not_client_credentials():
    outputs = analyze_resource_evidence([
        obj("validating", "ValidatingWebhookConfiguration", "policy", webhooks=[{
            "name": "policy.example.com",
            "failurePolicy": "Fail",
            "timeoutSeconds": 5,
            "sideEffects": "None",
            "clientConfig": {"url": "https://webhook.internal", "caBundle": "VERY-SENSITIVE-CA-DATA"},
        }]),
        obj("mutating", "MutatingWebhookConfiguration", "injector", webhooks=[{
            "name": "inject.example.com",
            "failurePolicy": "Ignore",
            "timeoutSeconds": 3,
            "sideEffects": "None",
            "clientConfig": {"service": {"name": "injector", "namespace": "system"}},
        }]),
    ])
    validating = output_for(outputs, "validatingwebhookconfiguration")
    mutating = output_for(outputs, "mutatingwebhookconfiguration")
    assert validating["webhooks"][0] == {
        "name": "policy.example.com", "failure_policy": "Fail", "timeout_seconds": 5, "side_effects": "None"
    }
    assert mutating["webhooks"][0]["failure_policy"] == "Ignore"
    assert "VERY-SENSITIVE-CA-DATA" not in json.dumps(outputs)


def test_secret_and_configmap_outputs_are_metadata_only():
    outputs = analyze_resource_evidence([
        obj("secret", "Secret", "db", metadata={"labels": {"app": "db"}}, data={"password": "SECRET-VALUE"}),
        obj("cm", "ConfigMap", "app", data={"mode": "PRIVATE-CONFIG"}),
    ])
    rendered = json.dumps(outputs)
    assert "SECRET-VALUE" not in rendered
    assert "PRIVATE-CONFIG" not in rendered
    assert output_for(outputs, "secret")["payload_redacted"] is True
    assert output_for(outputs, "configmap")["payload_redacted"] is True


def test_diagnostics_builder_exposes_independent_stage_outputs_and_registry():
    result = build_kubernetes_analysis([
        obj("ds", "DaemonSet", "node-agent", status={
            "desiredNumberScheduled": 3,
            "numberReady": 2,
            "numberUnavailable": 1,
            "numberMisscheduled": 0,
        }),
        obj("pdb", "PodDisruptionBudget", "agent-pdb", status={"disruptionsAllowed": 0, "currentHealthy": 2, "desiredHealthy": 2}),
    ], service_name="node-agent")

    assert result["resource_stage_outputs"]
    assert "daemonset" in result["resource_analyzer_registry"]
    assert "poddisruptionbudget" in result["resource_analyzer_registry"]
    assert result["resource_analyzer_output_count"] == 2
    assert result["diagnostic_stages"][1] == "independent_resource_analyzers"
    codes = {row["code"] for row in result["findings"]}
    assert "daemonset_unavailable" in codes
    assert "pdb_blocking_condition" in codes
