from __future__ import annotations

import asyncio
import json
import os
import shlex
from typing import Any, Dict

from mcp_servers.vm_management.config import VMManagementSettings
from mcp_servers.vm_management.inventory import VMRecord
from mcp_servers.vm_management.transports.base import VMTransport


class OpenSSHTransport(VMTransport):
    """Allowlisted VM operations over the system OpenSSH client.

    Callers never provide a command. Remote commands are fixed templates selected
    by capability handlers. Inventory validation constrains target/service input.
    """

    def __init__(self, settings: VMManagementSettings):
        self.settings = settings
        self._semaphore = asyncio.Semaphore(settings.MAX_CONCURRENCY)

    def _identity_file(self, vm: VMRecord) -> str:
        path = str(os.environ.get(vm.credential_ref, "")).strip()
        if not path:
            raise PermissionError("vm_credential_not_configured")
        return path

    def _ssh_args(self, vm: VMRecord, command: str) -> list[str]:
        args = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.settings.SSH_CONNECT_TIMEOUT}",
            "-o", "IdentitiesOnly=yes",
            "-o", "LogLevel=ERROR",
            "-p", str(vm.ssh_port),
            "-i", self._identity_file(vm),
        ]
        if self.settings.SSH_STRICT_HOST_KEY_CHECKING:
            args += [
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.settings.SSH_KNOWN_HOSTS}",
            ]
        else:
            args += ["-o", "StrictHostKeyChecking=accept-new"]
        args += [f"{vm.ssh_user}@{vm.ip}", command]
        return args

    async def _run(self, vm: VMRecord, command: str) -> Dict[str, Any]:
        async with self._semaphore:
            process = await asyncio.create_subprocess_exec(
                *self._ssh_args(vm, command),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=self.settings.SSH_COMMAND_TIMEOUT
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                raise TimeoutError("vm_ssh_command_timeout")
        output = stdout.decode("utf-8", errors="replace").strip()
        error = stderr.decode("utf-8", errors="replace").strip()
        if process.returncode != 0:
            raise RuntimeError(f"vm_ssh_command_failed:exit={process.returncode}:{error[:400]}")
        return {"exit_code": int(process.returncode or 0), "stdout": output}

    async def collect_vm_metrics(self, vm: VMRecord) -> Dict[str, Any]:
        command = (
            "python3 -c "
            + shlex.quote(
                "import json,os; "
                "la=os.getloadavg(); "
                "print(json.dumps({'load_1m':la[0],'load_5m':la[1],'load_15m':la[2]}))"
            )
        )
        result = await self._run(vm, command)
        try:
            metrics = json.loads(result["stdout"] or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("vm_metrics_invalid_json") from exc
        return {"metrics": metrics, "exit_code": result["exit_code"]}

    async def service_status(self, vm: VMRecord, service: str) -> Dict[str, Any]:
        svc = shlex.quote(service)
        result = await self._run(
            vm,
            f"systemctl show {svc} --no-pager --property=ActiveState,SubState,UnitFileState,MainPID",
        )
        fields: Dict[str, Any] = {}
        for line in result["stdout"].splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value
        return {"service": service, "status": fields, "exit_code": result["exit_code"]}

    async def process_snapshot(self, vm: VMRecord) -> Dict[str, Any]:
        result = await self._run(vm, "ps -eo pid,comm,pcpu,pmem --sort=-pcpu | head -n 21")
        return {"processes": result["stdout"].splitlines(), "exit_code": result["exit_code"]}

    async def restart_service(self, vm: VMRecord, service: str) -> Dict[str, Any]:
        svc = shlex.quote(service)
        result = await self._run(
            vm,
            f"sudo -n systemctl restart {svc} && systemctl is-active {svc}",
        )
        return {
            "service": service,
            "active_state": result["stdout"].splitlines()[-1] if result["stdout"] else "unknown",
            "exit_code": result["exit_code"],
        }
