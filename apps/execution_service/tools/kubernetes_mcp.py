from __future__ import annotations

from apps.execution_service.tools.base import BaseTool, ToolInput, ToolOutput
from integrations.kubernetes.mcp_client import KubernetesMCPClient


class KubernetesMCPTool(BaseTool):
    """High-risk Kubernetes mutations through the governed Kubernetes MCP only."""

    ACTIONS = {"restart_workload", "rollback_workload", "scale_workload"}

    def __init__(self, connector: KubernetesMCPClient | None = None):
        self.connector = connector

    def _connector(self) -> KubernetesMCPClient:
        if self.connector is None:
            self.connector = KubernetesMCPClient()
        return self.connector

    @property
    def name(self) -> str:
        return "kubernetes_mcp"

    @property
    def risk_level(self) -> str:
        return "high"

    @property
    def requires_approval(self) -> bool:
        return True

    async def validate(self, input_data: ToolInput) -> bool:
        params = input_data.parameters or {}
        if not input_data.target or input_data.action not in self.ACTIONS:
            return False
        if not str(params.get("namespace") or ""):
            return False
        if not input_data.approval_id or not input_data.incident_id or not input_data.execution_capability:
            return False
        if input_data.action == "scale_workload":
            replicas = params.get("replicas")
            if isinstance(replicas, bool) or not isinstance(replicas, int) or not 0 <= replicas <= 100:
                return False
        if input_data.action == "rollback_workload" and params.get("revision") is not None and not str(params.get("revision") or "").strip():
            return False
        return True

    async def execute(self, input_data: ToolInput) -> ToolOutput:
        connector = self._connector()
        params = input_data.parameters or {}
        namespace = str(params["namespace"])
        approval_id = str(input_data.approval_id or "")
        incident_id = str(input_data.incident_id or "")
        capability = str(input_data.execution_capability or "")
        try:
            if input_data.action == "restart_workload":
                result = await connector.restart_workload(input_data.target, namespace, approval_id, incident_id, capability)
            elif input_data.action == "rollback_workload":
                revision = str(params["revision"]) if params.get("revision") is not None else None
                result = await connector.rollback_workload(input_data.target, namespace, approval_id, incident_id, capability, revision)
            elif input_data.action == "scale_workload":
                result = await connector.scale_workload(input_data.target, namespace, int(params["replicas"]), approval_id, incident_id, capability)
            else:
                result = {"success": False, "error": "unsupported_action"}
        except (RuntimeError, PermissionError, ValueError) as exc:
            return ToolOutput(success=False, result={"error": str(exc)}, error=str(exc))
        return ToolOutput(success=bool(result.get("success")), result=result, error=result.get("error"))
