from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from mcp_servers.vm_management.inventory import VMRecord


class VMTransport(ABC):
    @abstractmethod
    async def collect_vm_metrics(self, vm: VMRecord) -> Dict[str, Any]: ...

    @abstractmethod
    async def service_status(self, vm: VMRecord, service: str) -> Dict[str, Any]: ...

    @abstractmethod
    async def process_snapshot(self, vm: VMRecord) -> Dict[str, Any]: ...

    @abstractmethod
    async def restart_service(self, vm: VMRecord, service: str) -> Dict[str, Any]: ...

    async def close(self) -> None:
        return None
