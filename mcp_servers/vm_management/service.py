from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict

from mcp_servers.vm_management.config import VMManagementSettings
from mcp_servers.vm_management.inventory import VMInventory
from mcp_servers.vm_management.transports.base import VMTransport

_APPROVAL_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
READ_TOOLS = {"collect_vm_metrics", "service_status", "process_snapshot"}
WRITE_TOOLS = {"restart_service"}
ALL_TOOLS = READ_TOOLS | WRITE_TOOLS


class VMManagementService:
    def __init__(self, settings: VMManagementSettings, inventory: VMInventory, transport: VMTransport):
        self.settings = settings
        self.inventory = inventory
        self.transport = transport

    def tools(self) -> list[dict[str, Any]]:
        schemas = {
            "collect_vm_metrics": {"target": {"type": "string"}},
            "service_status": {"target": {"type": "string"}, "service": {"type": "string"}},
            "process_snapshot": {"target": {"type": "string"}},
            "restart_service": {
                "target": {"type": "string"},
                "service": {"type": "string"},
                "approval_id": {"type": "string"},
            },
        }
        required = {
            "collect_vm_metrics": ["target"],
            "service_status": ["target", "service"],
            "process_snapshot": ["target"],
            "restart_service": ["target", "service", "approval_id"],
        }
        return [
            {
                "name": name,
                "description": f"Governed VM capability: {name}",
                "inputSchema": {"type": "object", "properties": schemas[name], "required": required[name], "additionalProperties": False},
                "annotations": {"readOnlyHint": name in READ_TOOLS, "destructiveHint": name in WRITE_TOOLS},
            }
            for name in sorted(ALL_TOOLS)
        ]

    async def call(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        started = time.perf_counter()
        timestamp = datetime.now(timezone.utc).isoformat()
        if tool not in ALL_TOOLS:
            raise PermissionError("vm_tool_not_allowed")
        target = str(arguments.get("target", "")).strip()
        service = str(arguments.get("service", "")).strip() or None
        approval_id = str(arguments.get("approval_id", "")).strip() or None
        if not target:
            raise ValueError("vm_target_required")
        if tool in WRITE_TOOLS:
            if not self.settings.WRITE_ENABLED:
                raise PermissionError("vm_write_disabled")
            if not approval_id or not _APPROVAL_RE.fullmatch(approval_id):
                raise PermissionError("vm_valid_approval_id_required")
        vm = self.inventory.authorize(target, tool, service)
        if tool == "collect_vm_metrics":
            data = await self.transport.collect_vm_metrics(vm)
        elif tool == "service_status":
            if not service:
                raise ValueError("vm_service_required")
            data = await self.transport.service_status(vm, service)
        elif tool == "process_snapshot":
            data = await self.transport.process_snapshot(vm)
        elif tool == "restart_service":
            if not service:
                raise ValueError("vm_service_required")
            data = await self.transport.restart_service(vm, service)
        else:
            raise PermissionError("vm_tool_not_allowed")
        finished = datetime.now(timezone.utc).isoformat()
        return {
            "success": True,
            "target": vm.id,
            "resolved_ip": vm.ip,
            "tool": tool,
            "timestamp": timestamp,
            "data": data,
            "error": None,
            "execution": {
                "mode": "write" if tool in WRITE_TOOLS else "read",
                "approval_id": approval_id,
                "execution_started_at": timestamp,
                "execution_finished_at": finished,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            },
        }
