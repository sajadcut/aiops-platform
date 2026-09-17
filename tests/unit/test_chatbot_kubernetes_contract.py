from pathlib import Path

import pytest

from apps.mcp_server.main import _TOOL_SCHEMAS
from integrations.kubernetes.client import KubernetesEvidenceClient
from integrations.kubernetes.mcp_client import KubernetesMCPClient


def test_kubernetes_chatbot_reads_extend_existing_mcp_tool_not_tool_names():
    assert set(_TOOL_SCHEMAS["kubernetes"]) == {"collect_kubernetes_evidence"}
    schema = _TOOL_SCHEMAS["kubernetes"]["collect_kubernetes_evidence"]["inputSchema"]
    allowed = set(schema["properties"]["operation"]["enum"])
    assert allowed == KubernetesMCPClient.READ_OPERATIONS
    assert "exec" not in allowed
    assert "apply" not in allowed
    assert "delete" not in allowed


def test_kubernetes_native_evidence_client_remains_get_only():
    source = Path("integrations/kubernetes/client.py").read_text(encoding="utf-8")
    assert "client.get(" in source
    assert "client.post(" not in source
    assert "client.put(" not in source
    assert "client.patch(" not in source
    assert "client.delete(" not in source
    assert "subprocess" not in source
    assert "kubectl" not in source


@pytest.mark.asyncio
async def test_kubernetes_read_operations_are_normalized_without_direct_api_mutation(monkeypatch):
    client = KubernetesEvidenceClient(api_url="https://kubernetes.invalid", token="test", namespace="payments")

    async def fake_get(path, params=None):
        if path.endswith("/pods") and "metrics.k8s.io" not in path:
            return {"items": [{"metadata": {"name": "payment-api-1", "namespace": "payments"}, "status": {"phase": "Running"}, "spec": {"nodeName": "node-a"}}]}
        if "/deployments/" in path:
            return {
                "metadata": {"name": "payment-api", "namespace": "payments", "generation": 3},
                "spec": {"replicas": 2},
                "status": {"observedGeneration": 3, "replicas": 2, "updatedReplicas": 2, "readyReplicas": 2, "availableReplicas": 2},
            }
        if "metrics.k8s.io" in path:
            return {"items": [{"metadata": {"name": "payment-api-1"}, "containers": []}]}
        if path.endswith("/events"):
            return {"items": []}
        raise AssertionError(path)

    monkeypatch.setattr(client, "_get", fake_get)
    pods = await client.collect_query(operation="list_pods", namespace="payments")
    assert pods[0]["name"] == "payment-api-1"
    assert pods[0]["phase"] == "Running"

    rollout = await client.collect_query(operation="rollout_state", namespace="payments", resource="payment-api")
    assert rollout["rollout_complete"] is True

    metrics = await client.collect_query(operation="resource_usage", namespace="payments")
    assert metrics[0]["metadata"]["name"] == "payment-api-1"


@pytest.mark.asyncio
async def test_kubernetes_mcp_client_sends_only_allowlisted_read_tool(monkeypatch):
    client = object.__new__(KubernetesMCPClient)
    captured = {}

    async def fake_call_tool(name, arguments):
        captured["name"] = name
        captured["arguments"] = arguments
        return {"content": [{"name": "pod-a", "phase": "Running"}]}

    monkeypatch.setattr(client, "call_tool", fake_call_tool)
    result = await client.collect_query(operation="list_pods", namespace="payments")
    assert captured["name"] == "collect_kubernetes_evidence"
    assert captured["arguments"] == {"operation": "list_pods", "namespace": "payments"}
    assert result == {"name": "pod-a", "phase": "Running"}

    with pytest.raises(ValueError, match="unsupported_kubernetes_read_operation"):
        await client.collect_query(operation="delete_pod", namespace="payments")
