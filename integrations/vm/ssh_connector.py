from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, Optional

from domain.contracts.config import settings
from domain.contracts.logging import logger

_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:-]+$")
_SAFE_SERVICE = re.compile(r"^[A-Za-z0-9@_.:-]+$")


class SSHVMConnector:
    """Controlled Linux VM adapter using noninteractive, allowlisted OpenSSH operations."""

    source_name = "vm_ssh"

    def __init__(self, timeout: Optional[int] = None):
        self.timeout = timeout or settings.SSH_CONNECT_TIMEOUT

    def _validate_target(self, target: str) -> None:
        if not target or not _SAFE_HOST.fullmatch(target):
            raise ValueError("invalid_vm_target")
        allowed = {str(item).strip() for item in settings.VM_ALLOWED_TARGETS if str(item).strip()}
        if allowed and target not in allowed:
            raise PermissionError("vm_target_not_allowlisted")

    def _validate_service(self, service: str) -> None:
        if not service or not _SAFE_SERVICE.fullmatch(service):
            raise ValueError("invalid_service_name")
        allowed = {str(item).strip() for item in settings.VM_ALLOWED_SERVICES if str(item).strip()}
        if allowed and service not in allowed:
            raise PermissionError("vm_service_not_allowlisted")

    def _base_ssh_args(self, target: str) -> list[str]:
        self._validate_target(target)
        if settings.APP_ENV == "production":
            if not settings.SSH_STRICT_HOST_KEY_CHECKING:
                raise RuntimeError("production_ssh_requires_strict_host_key_checking")
            if not settings.SSH_KNOWN_HOSTS:
                raise RuntimeError("production_ssh_known_hosts_required")
            if not settings.SSH_PRIVATE_KEY_PATH:
                raise RuntimeError("production_ssh_private_key_required")
            if not settings.SSH_USERNAME.strip() or settings.SSH_USERNAME.strip().lower() == "root":
                raise RuntimeError("production_ssh_non_root_username_required")

        args = [
            "ssh",
            "-p",
            str(settings.SSH_PORT),
            "-o",
            f"ConnectTimeout={self.timeout}",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
        ]
        strict = settings.SSH_STRICT_HOST_KEY_CHECKING
        args += ["-o", f"StrictHostKeyChecking={'yes' if strict else 'no'}"]
        if settings.SSH_KNOWN_HOSTS:
            args += ["-o", f"UserKnownHostsFile={settings.SSH_KNOWN_HOSTS}"]
        if settings.SSH_PRIVATE_KEY_PATH:
            args += ["-o", "IdentitiesOnly=yes", "-i", settings.SSH_PRIVATE_KEY_PATH]
        user = settings.SSH_USERNAME.strip()
        destination = f"{user}@{target}" if user else target
        args.append(destination)
        return args

    async def _run(self, target: str, command: str) -> Dict[str, Any]:
        args = self._base_ssh_args(target) + ["--", command]
        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout + 5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {"success": False, "error": "ssh_command_timeout"}
        elapsed = time.perf_counter() - started
        return {
            "success": process.returncode == 0,
            "exit_code": process.returncode,
            "stdout": stdout.decode(errors="replace").strip(),
            "stderr": stderr.decode(errors="replace").strip(),
            "execution_time": elapsed,
        }

    async def health_check(self, target: str) -> bool:
        result = await self._run(target, "printf connected")
        return bool(result.get("success")) and result.get("stdout") == "connected"

    async def collect_metrics(self, target: str) -> Dict[str, Any]:
        command = (
            "LC_ALL=C; "
            "cpu=$(awk '/^cpu / {usage=($2+$4)*100/($2+$4+$5); printf \"%.2f\", usage}' /proc/stat); "
            "mem=$(free | awk '/^Mem:/ {printf \"%.2f\", ($3/$2)*100}'); "
            "load=$(awk '{printf \"%s,%s,%s\", $1,$2,$3}' /proc/loadavg); "
            "iowait=$(awk '/^cpu / {printf \"%.2f\", ($6)*100/($2+$4+$5+$6+$7+$8+$9)}' /proc/stat); "
            "printf '{\"cpu_usage\":%s,\"memory_usage\":%s,\"load_avg\":\"%s\",\"io_wait\":%s}' \"$cpu\" \"$mem\" \"$load\" \"$iowait\""
        )
        result = await self._run(target, command)
        if not result.get("success"):
            return result
        try:
            payload = json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"success": False, "error": "invalid_metric_payload"}
        return {"success": True, "metrics": payload, "execution_time": result.get("execution_time")}

    async def service_status(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._run(target, f"systemctl is-active {service}")
        return {"success": result.get("success", False), "service": service, "status": result.get("stdout"), "error": result.get("stderr")}

    async def restart_service(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._run(target, f"sudo -n systemctl restart {service}")
        if not result.get("success"):
            logger.warning("vm_service_restart_failed", target=target, service=service, error_type="ssh_command_failed")
        return {"success": result.get("success", False), "service": service, "target": target, "error": "restart_failed" if not result.get("success") else None}

    async def process_snapshot(self, target: str) -> Dict[str, Any]:
        result = await self._run(target, "ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 11")
        return {"success": result.get("success", False), "processes": result.get("stdout", ""), "error": "process_snapshot_failed" if not result.get("success") else None}
