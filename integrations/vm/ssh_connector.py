from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, Optional

import asyncssh

from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.vm.service_adapters import get_service_adapter

_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:-]+$")
_SAFE_SERVICE = re.compile(r"^[A-Za-z0-9@_.:-]+$")


class SSHVMConnector:
    """Controlled Linux VM adapter used only behind the VM MCP server.

    The adapter exposes fixed diagnostic operations instead of arbitrary shell
    execution. User-controlled targets/services are validated and allowlisted.
    Passwords are handed only to AsyncSSH and never placed in process arguments
    or logs.
    """

    source_name = "vm_ssh"

    def __init__(self, timeout: Optional[int] = None):
        self.timeout = timeout or settings.SSH_CONNECT_TIMEOUT
        self._validate_runtime_security()

    @staticmethod
    def _auth_mode() -> str:
        return str(settings.SSH_AUTH_MODE or "").strip().lower()

    @staticmethod
    def _password() -> str:
        return str(settings.SSH_PASSWORD or "")

    @classmethod
    def _validate_runtime_security(cls) -> None:
        auth_mode = cls._auth_mode()
        errors: list[str] = []
        if auth_mode not in {"key", "password"}:
            errors.append("SSH_AUTH_MODE must be key or password")
        if auth_mode == "password":
            if not settings.SSH_USERNAME.strip():
                errors.append("SSH_USERNAME is required for password authentication")
            if not cls._password():
                errors.append("SSH_PASSWORD is required for password authentication")

        if settings.APP_ENV != "production":
            if errors:
                raise RuntimeError("vm_ssh_configuration_invalid:" + ";".join(errors))
            return

        if not settings.SSH_ENABLED:
            errors.append("SSH_ENABLED must be true on the isolated VM MCP server")
        if not settings.SSH_STRICT_HOST_KEY_CHECKING:
            errors.append("SSH_STRICT_HOST_KEY_CHECKING must be true")
        if not settings.SSH_KNOWN_HOSTS:
            errors.append("SSH_KNOWN_HOSTS is required")
        if auth_mode == "key" and not settings.SSH_PRIVATE_KEY_PATH:
            errors.append("SSH_PRIVATE_KEY_PATH is required for key authentication")
        username = settings.SSH_USERNAME.strip().lower()
        if not username:
            errors.append("SSH_USERNAME is required")
        elif username == "root":
            errors.append("root SSH is forbidden")
        if not settings.SSH_ALLOWED_TARGETS:
            errors.append("SSH_ALLOWED_TARGETS must not be empty")
        if not settings.SSH_ALLOWED_SERVICES:
            errors.append("SSH_ALLOWED_SERVICES must not be empty")
        if errors:
            raise RuntimeError("vm_ssh_configuration_invalid:" + ";".join(errors))

    def _validate_target(self, target: str) -> None:
        if not target or not _SAFE_HOST.fullmatch(target):
            raise ValueError("invalid_vm_target")
        allowed = {str(item).strip() for item in settings.SSH_ALLOWED_TARGETS if str(item).strip()}
        if allowed and target not in allowed:
            raise PermissionError("vm_target_not_allowed")

    @staticmethod
    def _validate_remote_host(host: str) -> None:
        if not host or not _SAFE_HOST.fullmatch(host):
            raise ValueError("invalid_remote_host")

    def _validate_service(self, service: str) -> None:
        if not service or not _SAFE_SERVICE.fullmatch(service):
            raise ValueError("invalid_service_name")
        allowed = {str(item).strip() for item in settings.SSH_ALLOWED_SERVICES if str(item).strip()}
        if allowed and service not in allowed:
            raise PermissionError("vm_service_not_allowed")

    @staticmethod
    def _validate_port(port: int) -> int:
        value = int(port)
        if value < 1 or value > 65535:
            raise ValueError("invalid_tcp_port")
        return value

    @staticmethod
    def _bounded_limit(limit: int, maximum: int = 200) -> int:
        return min(max(int(limit or 1), 1), maximum)

    def _base_ssh_args(self, target: str) -> list[str]:
        self._validate_target(target)
        args = [
            "ssh", "-p", str(settings.SSH_PORT), "-o", f"ConnectTimeout={self.timeout}",
            "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
        ]
        strict = settings.SSH_STRICT_HOST_KEY_CHECKING
        args += ["-o", f"StrictHostKeyChecking={'yes' if strict else 'no'}"]
        if settings.SSH_KNOWN_HOSTS:
            args += ["-o", f"UserKnownHostsFile={settings.SSH_KNOWN_HOSTS}"]
        if settings.SSH_PRIVATE_KEY_PATH:
            args += ["-o", "IdentitiesOnly=yes", "-i", settings.SSH_PRIVATE_KEY_PATH]
        user = settings.SSH_USERNAME.strip()
        args.append(f"{user}@{target}" if user else target)
        return args

    async def _run_key(self, target: str, command: str) -> Dict[str, Any]:
        args = self._base_ssh_args(target) + ["--", command]
        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout + 5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            logger.warning("vm_ssh_command_timeout", target=target, auth_mode="key", duration_ms=duration_ms)
            return {"success": False, "error": "ssh_command_timeout", "execution_time": duration_ms / 1000.0}
        elapsed = time.perf_counter() - started
        duration_ms = round(elapsed * 1000, 3)
        success = process.returncode == 0
        logger.info(
            "vm_ssh_command_completed",
            target=target,
            auth_mode="key",
            success=success,
            exit_code=process.returncode,
            duration_ms=duration_ms,
        )
        if not success:
            logger.warning(
                "vm_ssh_command_failed",
                target=target,
                exit_code=process.returncode,
                auth_mode="key",
                duration_ms=duration_ms,
            )
        return {
            "success": success, "exit_code": process.returncode,
            "stdout": stdout.decode(errors="replace").strip(),
            "stderr": stderr.decode(errors="replace").strip(), "execution_time": elapsed,
        }

    async def _run_password(self, target: str, command: str) -> Dict[str, Any]:
        self._validate_target(target)
        username = settings.SSH_USERNAME.strip()
        password = self._password()
        if not username or not password:
            raise RuntimeError("vm_ssh_password_credentials_required")
        if settings.SSH_STRICT_HOST_KEY_CHECKING:
            if not settings.SSH_KNOWN_HOSTS:
                raise RuntimeError("vm_ssh_known_hosts_required")
            known_hosts: str | None = settings.SSH_KNOWN_HOSTS
        else:
            known_hosts = None
        started = time.perf_counter()

        async def execute() -> Dict[str, Any]:
            async with asyncssh.connect(
                target, port=settings.SSH_PORT, username=username, password=password,
                client_keys=[], known_hosts=known_hosts,
            ) as connection:
                result = await connection.run(command, check=False)
                return {
                    "success": result.exit_status == 0, "exit_code": result.exit_status,
                    "stdout": str(result.stdout or "").strip(),
                    "stderr": str(result.stderr or "").strip(),
                }

        try:
            result = await asyncio.wait_for(execute(), timeout=self.timeout + 5)
        except asyncio.TimeoutError:
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            logger.warning("vm_ssh_command_timeout", target=target, auth_mode="password", duration_ms=duration_ms)
            return {"success": False, "error": "ssh_command_timeout", "execution_time": duration_ms / 1000.0}
        except (asyncssh.Error, OSError) as exc:
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            logger.warning(
                "vm_ssh_command_failed",
                target=target,
                auth_mode="password",
                error_type=type(exc).__name__,
                duration_ms=duration_ms,
            )
            return {"success": False, "error": "ssh_command_failed", "execution_time": duration_ms / 1000.0}
        result["execution_time"] = time.perf_counter() - started
        duration_ms = round(float(result["execution_time"]) * 1000, 3)
        logger.info(
            "vm_ssh_command_completed",
            target=target,
            auth_mode="password",
            success=bool(result.get("success")),
            exit_code=result.get("exit_code"),
            duration_ms=duration_ms,
        )
        if not result.get("success"):
            logger.warning(
                "vm_ssh_command_failed",
                target=target,
                exit_code=result.get("exit_code"),
                auth_mode="password",
                duration_ms=duration_ms,
            )
        return result

    async def _run(self, target: str, command: str) -> Dict[str, Any]:
        if self._auth_mode() == "password":
            return await self._run_password(target, command)
        return await self._run_key(target, command)

    async def health_check(self, target: str) -> bool:
        result = await self._run(target, "printf connected")
        return bool(result.get("success")) and result.get("stdout") == "connected"

    @staticmethod
    def _parse_cpu_counters(value: str) -> tuple[int, ...]:
        parts = value.split()
        if len(parts) != 8:
            raise ValueError("invalid_cpu_counter_sample")
        counters = tuple(int(part) for part in parts)
        if any(counter < 0 for counter in counters):
            raise ValueError("invalid_cpu_counter_sample")
        return counters

    @classmethod
    def _cpu_interval_percentages(cls, first: str, second: str) -> tuple[float, float]:
        start = cls._parse_cpu_counters(first)
        end = cls._parse_cpu_counters(second)
        deltas = tuple(after - before for before, after in zip(start, end))
        if any(delta < 0 for delta in deltas):
            raise ValueError("cpu_counter_reset")
        total_delta = sum(deltas)
        if total_delta <= 0:
            raise ValueError("cpu_counter_delta_zero")
        idle_delta = deltas[3] + deltas[4]
        busy_delta = total_delta - idle_delta
        if busy_delta < 0:
            raise ValueError("invalid_cpu_counter_delta")
        cpu_usage = round((busy_delta * 100.0) / total_delta, 2)
        io_wait = round((deltas[4] * 100.0) / total_delta, 2)
        return cpu_usage, io_wait

    async def collect_metrics(self, target: str) -> Dict[str, Any]:
        command = (
            "LC_ALL=C; "
            "printf 'CPU1 '; awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8,$9; exit}' /proc/stat; "
            "sleep 1; "
            "printf 'CPU2 '; awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8,$9; exit}' /proc/stat; "
            "free | awk '/^Mem:/ {printf \"MEM %.2f\\n\", ($3/$2)*100} /^Swap:/ {if ($2>0) printf \"SWAP %.2f\\n\", ($3/$2)*100; else printf \"SWAP 0.00\\n\"}'; "
            "awk '{printf \"LOAD %s,%s,%s\\n\", $1,$2,$3}' /proc/loadavg"
        )
        result = await self._run(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "error": "ssh_command_failed", "execution_time": result.get("execution_time")}
        try:
            fields: Dict[str, str] = {}
            for raw_line in str(result.get("stdout") or "").splitlines():
                key, separator, value = raw_line.strip().partition(" ")
                if separator and key in {"CPU1", "CPU2", "MEM", "SWAP", "LOAD"}:
                    fields[key] = value.strip()
            if set(fields) != {"CPU1", "CPU2", "MEM", "SWAP", "LOAD"}:
                raise ValueError("missing_metric_fields")
            cpu_usage, io_wait = self._cpu_interval_percentages(fields["CPU1"], fields["CPU2"])
            memory_usage = round(float(fields["MEM"]), 2)
            swap_usage = round(float(fields["SWAP"]), 2)
            if not 0.0 <= memory_usage <= 100.0 or not 0.0 <= swap_usage <= 100.0:
                raise ValueError("invalid_memory_metric")
            payload = {
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "swap_usage": swap_usage,
                "load_avg": fields["LOAD"],
                "io_wait": io_wait,
            }
        except (TypeError, ValueError):
            return {"success": False, "target": target, "error": "invalid_metric_payload"}
        return {"success": True, "target": target, "metrics": payload, "execution_time": result.get("execution_time")}

    async def host_info(self, target: str) -> Dict[str, Any]:
        command = (
            "LC_ALL=C; printf 'hostname=%s\\n' \"$(hostname 2>/dev/null)\"; "
            "printf 'kernel=%s\\n' \"$(uname -srmo 2>/dev/null)\"; "
            "printf 'uptime_seconds=%s\\n' \"$(awk '{print int($1)}' /proc/uptime 2>/dev/null)\"; "
            "printf 'timezone=%s\\n' \"$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)\"; "
            "if [ -r /etc/os-release ]; then . /etc/os-release; printf 'os_id=%s\\n' \"$ID\"; "
            "printf 'os_version=%s\\n' \"$VERSION_ID\"; printf 'os_name=%s\\n' \"$PRETTY_NAME\"; fi"
        )
        result = await self._run(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "error": "host_info_failed"}
        data: Dict[str, Any] = {}
        for line in str(result.get("stdout") or "").splitlines():
            key, sep, value = line.partition("=")
            if sep and key:
                data[key] = value
        if str(data.get("uptime_seconds", "")).isdigit():
            data["uptime_seconds"] = int(data["uptime_seconds"])
        return {"success": True, "target": target, "host": data}

    async def disk_status(self, target: str) -> Dict[str, Any]:
        result = await self._run(target, "LC_ALL=C; df -P -B1 2>/dev/null; printf '\\n__AIOPS_INODES__\\n'; df -Pi 2>/dev/null")
        if not result.get("success"):
            return {"success": False, "target": target, "error": "disk_status_failed"}
        disk_text, _, inode_text = str(result.get("stdout") or "").partition("__AIOPS_INODES__")

        def parse_df(value: str) -> list[Dict[str, Any]]:
            rows: list[Dict[str, Any]] = []
            lines = [line for line in value.splitlines() if line.strip()]
            for line in lines[1:]:
                parts = line.split(None, 5)
                if len(parts) == 6:
                    rows.append({"filesystem": parts[0], "blocks": parts[1], "used": parts[2], "available": parts[3], "use_percent": parts[4], "mount": parts[5]})
            return rows
        return {"success": True, "target": target, "filesystems": parse_df(disk_text), "inodes": parse_df(inode_text)}

    async def network_status(self, target: str) -> Dict[str, Any]:
        command = "if ! command -v ip >/dev/null 2>&1; then printf '__AIOPS_UNSUPPORTED__'; exit 0; fi; ip -j address 2>/dev/null; printf '\\n__AIOPS_ROUTES__\\n'; ip -j route 2>/dev/null"
        result = await self._run(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "error": "network_status_failed"}
        text = str(result.get("stdout") or "")
        if text == "__AIOPS_UNSUPPORTED__":
            return {"success": True, "supported": False, "target": target, "interfaces": [], "routes": []}
        addr_text, _, route_text = text.partition("__AIOPS_ROUTES__")
        try:
            interfaces = json.loads(addr_text.strip() or "[]")
            routes = json.loads(route_text.strip() or "[]")
        except json.JSONDecodeError:
            return {"success": False, "target": target, "error": "invalid_network_payload"}
        return {"success": True, "supported": True, "target": target, "interfaces": interfaces, "routes": routes}

    async def service_status(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        props = " --property=".join(["LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "ExecMainStatus", "NRestarts", "Result"])
        result = await self._run(target, f"systemctl show --no-pager --property={props} {service}")
        if not result.get("success"):
            return {"success": False, "target": target, "service": service, "status": "unknown", "error": "service_status_failed"}
        values: Dict[str, str] = {}
        for line in str(result.get("stdout") or "").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
        active_state = values.get("ActiveState", "unknown")
        return {
            "success": True, "target": target, "service": service,
            "load_state": values.get("LoadState"), "active_state": active_state,
            "sub_state": values.get("SubState"), "unit_file_state": values.get("UnitFileState"),
            "main_pid": int(values.get("MainPID", "0") or 0),
            "exec_main_status": int(values.get("ExecMainStatus", "0") or 0),
            "restart_count": int(values.get("NRestarts", "0") or 0), "result": values.get("Result"),
            "status": active_state, "healthy": active_state == "active", "error": None,
        }

    async def process_status(self, target: str, process: str) -> Dict[str, Any]:
        self._validate_service(process)
        result = await self._run(target, f"LC_ALL=C; ps -C {process} -o pid=,ppid=,stat=,comm=,%cpu=,%mem= 2>/dev/null || true")
        if not result.get("success"):
            return {"success": False, "target": target, "process": process, "error": "process_status_failed"}
        rows = []
        for line in str(result.get("stdout") or "").splitlines():
            parts = line.split()
            if len(parts) >= 6:
                try:
                    rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "state": parts[2], "command": parts[3], "cpu_percent": float(parts[4]), "memory_percent": float(parts[5])})
                except (TypeError, ValueError):
                    continue
        return {"success": True, "target": target, "process": process, "running": bool(rows), "count": len(rows), "processes": rows}

    async def process_snapshot(self, target: str) -> Dict[str, Any]:
        result = await self._run(target, "LC_ALL=C; ps -eo pid=,ppid=,stat=,comm=,%cpu=,%mem= --sort=-%cpu | head -n 25")
        if not result.get("success"):
            return {"success": False, "target": target, "processes": [], "error": "process_snapshot_failed"}
        rows = []
        for line in str(result.get("stdout") or "").splitlines():
            parts = line.split()
            if len(parts) >= 6:
                try:
                    rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "state": parts[2], "command": parts[3], "cpu_percent": float(parts[4]), "memory_percent": float(parts[5])})
                except (TypeError, ValueError):
                    continue
        return {"success": True, "target": target, "processes": rows, "error": None}

    async def service_logs(self, target: str, service: str, limit: int = 100) -> Dict[str, Any]:
        self._validate_service(service)
        bounded = self._bounded_limit(limit)
        result = await self._run(target, f"journalctl --no-pager -u {service} -n {bounded} -o short-iso 2>/dev/null")
        if not result.get("success"):
            return {"success": False, "target": target, "service": service, "logs": [], "error": "service_logs_failed"}
        lines = [line for line in str(result.get("stdout") or "").splitlines() if line.strip()]
        return {"success": True, "target": target, "service": service, "logs": lines[-bounded:], "count": len(lines[-bounded:])}

    async def system_logs(self, target: str, limit: int = 100) -> Dict[str, Any]:
        bounded = self._bounded_limit(limit)
        result = await self._run(target, f"journalctl --no-pager -n {bounded} -o short-iso 2>/dev/null")
        if not result.get("success"):
            return {"success": False, "target": target, "logs": [], "error": "system_logs_failed"}
        lines = [line for line in str(result.get("stdout") or "").splitlines() if line.strip()]
        return {"success": True, "target": target, "logs": lines[-bounded:], "count": len(lines[-bounded:])}

    async def tcp_check(self, target: str, host: str, port: int) -> Dict[str, Any]:
        self._validate_remote_host(host)
        value = self._validate_port(port)
        command = (
            f"host={host}; port={value}; if command -v nc >/dev/null 2>&1; then nc -z -w 3 \"$host\" \"$port\" >/dev/null 2>&1; rc=$?; "
            "elif command -v timeout >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then timeout 3 bash -c \"</dev/tcp/$host/$port\" >/dev/null 2>&1; rc=$?; "
            "else printf 'unsupported'; exit 0; fi; if [ \"$rc\" -eq 0 ]; then printf 'reachable'; else printf 'unreachable'; fi"
        )
        result = await self._run(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "host": host, "port": value, "error": "tcp_check_failed"}
        state = str(result.get("stdout") or "").strip()
        return {"success": True, "target": target, "host": host, "port": value, "supported": state != "unsupported", "reachable": True if state == "reachable" else False if state == "unreachable" else None}

    async def port_listener_status(self, target: str, port: int) -> Dict[str, Any]:
        value = self._validate_port(port)
        command = f"if ! command -v ss >/dev/null 2>&1; then printf '__AIOPS_UNSUPPORTED__'; exit 0; fi; ss -H -lntp 2>/dev/null | awk '$4 ~ /:{value}$/ {{print}}' | head -n 50"
        result = await self._run(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "port": value, "error": "port_listener_status_failed"}
        text = str(result.get("stdout") or "")
        if text == "__AIOPS_UNSUPPORTED__":
            return {"success": True, "supported": False, "target": target, "port": value, "listening": None, "listeners": []}
        lines = [line for line in text.splitlines() if line.strip()]
        return {"success": True, "supported": True, "target": target, "port": value, "listening": bool(lines), "listeners": lines}

    async def dns_check(self, target: str, hostname: str) -> Dict[str, Any]:
        self._validate_remote_host(hostname)
        result = await self._run(target, f"getent ahosts {hostname} 2>/dev/null | head -n 20")
        if not result.get("success"):
            return {"success": True, "target": target, "hostname": hostname, "resolved": False, "addresses": []}
        addresses = []
        for line in str(result.get("stdout") or "").splitlines():
            parts = line.split()
            if parts and parts[0] not in addresses:
                addresses.append(parts[0])
        return {"success": True, "target": target, "hostname": hostname, "resolved": bool(addresses), "addresses": addresses}

    async def route_check(self, target: str, destination: str) -> Dict[str, Any]:
        self._validate_remote_host(destination)
        result = await self._run(target, f"ip route get {destination} 2>/dev/null")
        if not result.get("success"):
            return {"success": True, "target": target, "destination": destination, "route_found": False, "route": ""}
        route = str(result.get("stdout") or "").strip()
        return {"success": True, "target": target, "destination": destination, "route_found": bool(route), "route": route}

    async def firewall_status(self, target: str) -> Dict[str, Any]:
        command = "if command -v nft >/dev/null 2>&1; then echo 'provider=nftables'; nft list ruleset 2>/dev/null | head -n 200; elif command -v firewall-cmd >/dev/null 2>&1; then echo 'provider=firewalld'; firewall-cmd --state 2>/dev/null; firewall-cmd --list-all 2>/dev/null | head -n 200; elif command -v iptables >/dev/null 2>&1; then echo 'provider=iptables'; iptables -S 2>/dev/null | head -n 200; else echo 'provider=unavailable'; fi"
        result = await self._run(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "error": "firewall_status_failed"}
        lines = str(result.get("stdout") or "").splitlines()
        provider = "unknown"
        if lines and lines[0].startswith("provider="):
            provider = lines[0].split("=", 1)[1]
            lines = lines[1:]
        return {"success": True, "target": target, "supported": provider != "unavailable", "provider": provider, "rules": lines}

    async def config_validate(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        adapter = get_service_adapter(service)
        if adapter is None or not adapter.config_check_command:
            return {"success": True, "supported": False, "target": target, "service": service, "valid": None, "detail": "config_validation_adapter_unavailable"}
        result = await self._run(target, adapter.config_check_command)
        if result.get("exit_code") == 127:
            return {"success": True, "supported": False, "target": target, "service": service, "valid": None, "detail": "config_validation_binary_unavailable"}
        detail = "\n".join(part for part in (str(result.get("stdout") or "").strip(), str(result.get("stderr") or "").strip()) if part)
        if not result.get("success"):
            return {
                "success": False,
                "supported": True,
                "target": target,
                "service": service,
                "adapter": adapter.canonical_name,
                "valid": None,
                "exit_code": result.get("exit_code"),
                "error": "config_validation_transport_failed",
                "detail": detail[:4000],
            }
        return {"success": True, "supported": True, "target": target, "service": service, "adapter": adapter.canonical_name, "valid": True, "exit_code": result.get("exit_code"), "detail": detail[:4000]}

    async def start_service(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._run(target, f"sudo -n systemctl start {service}")
        if not result.get("success"):
            logger.warning("vm_service_start_failed", target=target, service=service)
        return {"success": result.get("success", False), "service": service, "target": target, "error": None if result.get("success") else "service_start_failed"}

    async def restart_service(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._run(target, f"sudo -n systemctl restart {service}")
        if not result.get("success"):
            logger.warning("vm_service_restart_failed", target=target, service=service)
        return {"success": result.get("success", False), "service": service, "target": target, "error": None if result.get("success") else "service_restart_failed"}

    async def reload_service(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._run(target, f"sudo -n systemctl reload {service}")
        if not result.get("success"):
            logger.warning("vm_service_reload_failed", target=target, service=service)
        return {"success": result.get("success", False), "service": service, "target": target, "error": None if result.get("success") else "service_reload_failed"}