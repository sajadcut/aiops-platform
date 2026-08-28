from __future__ import annotations

import pytest

from apps.execution_service.tools.base import ToolInput
from apps.execution_service.tools.kubernetes_mcp import KubernetesMCPTool


class FakeKubernetesConnector:
    def __init__(self):
        self.calls = []

    async def restart_workload(self, target, namespace, approval_id, incident_id, execution_capability):
        self.calls.append(("restart", target, namespace, approval_id, incident_id, execution_capability))
        return {"success": True, "action": "restart"}

    async def rollback_workload(self, target, namespace, approval_id, incident_id, execution_capability, revision=None):
        self.calls.append(("rollback", target, namespace, approval_id, incident_id, execution_capability, revision))
        return {"success": True, "action": "rollback"}

    async def scale_workload(self, target, namespace, replicas, approval_id, incident_id, execution_capability):
        self.calls.append(("scale", target, namespace, replicas, approval_id, incident_id, execution_capability))
        return {"success": True, "action": "scale"}


@pytest.mark.asyncio
async def test_kubernetes_write_requires_complete_approval_binding():
    tool = KubernetesMCPTool(FakeKubernetesConnector())
    base = {"action": "restart_workload", "target": "deployment/payments", "parameters": {"namespace": "aiops-oat"}}
    assert await tool.validate(ToolInput(**base)) is False
    assert await tool.validate(ToolInput(**base, approval_id="a", incident_id="i")) is False
    assert await tool.validate(ToolInput(**base, approval_id="a", incident_id="i", execution_capability="cap")) is True


@pytest.mark.asyncio
async def test_kubernetes_scale_is_bounded_and_capability_is_forwarded():
    connector = FakeKubernetesConnector()
    tool = KubernetesMCPTool(connector)
    invalid = ToolInput(
        action="scale_workload", target="deployment/payments",
        parameters={"namespace": "aiops-oat", "replicas": 101},
        approval_id="approval-1", incident_id="incident-1", execution_capability="signed-cap",
    )
    assert await tool.validate(invalid) is False

    valid = invalid.model_copy(update={"parameters": {"namespace": "aiops-oat", "replicas": 4}})
    assert await tool.validate(valid) is True
    output = await tool.execute(valid)
    assert output.success is True
    assert connector.calls == [("scale", "deployment/payments", "aiops-oat", 4, "approval-1", "incident-1", "signed-cap")]


@pytest.mark.asyncio
async def test_kubernetes_tool_rejects_unknown_actions():
    tool = KubernetesMCPTool(FakeKubernetesConnector())
    request = ToolInput(
        action="delete_namespace", target="namespace/production", parameters={"namespace": "production"},
        approval_id="approval-1", incident_id="incident-1", execution_capability="signed-cap",
    )
    assert await tool.validate(request) is False
