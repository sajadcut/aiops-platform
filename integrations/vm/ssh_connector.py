from __future__ import annotations

import asyncio
import json
import re
import shlex
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import asyncssh

from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.contracts.redaction import redact_text
from integrations.vm.service_inventory import parse_systemd_services
from integrations.vm.block_devices import parse_block_devices, parse_mount_modes
from integrations.vm.service_adapters import (
    get_service_adapter, discover_config_path, config_check_for_path,
    parse_config_diagnostic,
)
from integrations.vm.runtime_discovery import parse_systemd_runtime
from integrations.vm.dotnet_local_validator import (
    remote_file_listing_command, remote_file_read_command,
    safe_json_files, validate_encoded_file, MAX_FILES,
)
from integrations.vm.nginx_config_review import nginx_review_command, local_nginx_review
from integrations.vm.nginx_config_inspection import nginx_inspection_command, parse_nginx_inspection

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

    def _command_deadline_seconds(self, command: str) -> int:
        """Keep SSH connection timeout short; bound trusted config guard work separately.

        This is *not* an SSH allowlist expansion. Only the existing fixed
        ephemeral POSIX guard, never generic remote shell or service actions,
        receives time to stage/check the candidate and perform sudo fallback.
        """
        permitted = (
            "sudo -n /bin/sh -s -- ",
            "sudo -k -S -p '' /bin/sh -s -- ",
        )
        if (command.startswith(permitted)
                and any(command.startswith(prefix + action + " ")
                        for prefix in permitted for action in ("apply", "validate"))):
            return max(self.timeout + 5, 60)
        # Local agent root guard uses a bounded, root-owned executable rather
        # than sudo /bin/sh -s. Its isolated validator and atomic CAS may take
        # longer than the SSH connection timeout, but remain bounded.
        if (command.startswith("sudo -n /usr/local/sbin/aiops-config-guard ")
                or command.startswith("sudo -k -S -p '' /usr/local/sbin/aiops-config-guard ")):
            return max(self.timeout + 5, 180)
        return self.timeout + 5

    async def _run_key(self, target: str, command: str, *, stdin_data: Optional[str] = None) -> Dict[str, Any]:
        args = self._base_ssh_args(target) + ["--", command]
        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin_data.encode('utf-8') if stdin_data is not None else None),
                timeout=self._command_deadline_seconds(command),
            )
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

    async def _run_password(self, target: str, command: str, *, stdin_data: Optional[str] = None) -> Dict[str, Any]:
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
                # Only password-protected sudo receives stdin; never interpolate
                # credentials into the command or create a PTY which might echo it.
                if stdin_data is None:
                    result = await connection.run(command, check=False)
                else:
                    result = await connection.run(command, check=False, input=stdin_data)
                return {
                    "success": result.exit_status == 0, "exit_code": result.exit_status,
                    "stdout": str(result.stdout or "").strip(),
                    "stderr": str(result.stderr or "").strip(),
                }

        try:
            result = await asyncio.wait_for(
                execute(), timeout=self._command_deadline_seconds(command)
            )
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
            return {
                "success": False,
                # A closed stdin pipe may mean that sudo rejected the request
                # early OR that an already-started guard lost its transport.
                # For an APPLY, never assume the production write did not run.
                "error": ("ssh_stdin_pipe_closed" if isinstance(exc, BrokenPipeError)
                          else "ssh_command_failed"),
                "execution_time": duration_ms / 1000.0,
            }
        # Remote programs may echo arbitrary stdin. Never return the SSH secret
        # through MCP results, API responses, audit entries or error details.
        for stream in ("stdout", "stderr"):
            result[stream] = str(result.get(stream) or "").replace(password, "[REDACTED]")
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

    async def _run(self, target: str, command: str, *, stdin_data: Optional[str] = None) -> Dict[str, Any]:
        if self._auth_mode() == "password":
            return await self._run_password(target, command, stdin_data=stdin_data)
        return await self._run_key(target, command, stdin_data=stdin_data)

    @staticmethod
    def _sudo_requires_password(result: Dict[str, Any]) -> bool:
        output = (str(result.get("stderr") or "") + " " + str(result.get("stdout") or "")).lower()
        return not result.get("success") and (
            "a password is required" in output
            or "no tty present and no askpass program specified" in output
            or "a terminal is required to read the password" in output
        )

    async def _sudo(self, target: str, fixed_command: str, *,
                    stdin_data: Optional[str] = None) -> Dict[str, Any]:
        """Execute a fixed privileged action through the existing SSH user.

        When sudo requires an SSH-password-authenticated user's password,
        pass it via stdin. Do not log credential or candidate bytes.
        """
        is_guard = (fixed_command.startswith("/usr/local/sbin/aiops-config-guard ") or
                    fixed_command.startswith("/bin/sh -s -- "))
        first = (await self._run(target, f"sudo -n {fixed_command}")
                 if stdin_data is None else
                 await self._run(target, f"sudo -n {fixed_command}", stdin_data=stdin_data))
        needs_password = self._sudo_requires_password(first)
        if is_guard:
            logger.info(
                "vm_config_guard_sudo_stage",
                target=target, stage="sudo_noninteractive",
                ssh_user=settings.SSH_USERNAME.strip(),
                success=first.get("success") is True,
                exit_code=first.get("exit_code"),
                password_required=needs_password,
            )
        if not needs_password or self._auth_mode() != "password":
            return first
        password = self._password()
        if not password or "\n" in password or "\r" in password:
            if is_guard:
                logger.warning(
                    "vm_config_guard_sudo_stage",
                    target=target, stage="sudo_password_unavailable",
                    success=False,
                )
            return first
        # -k forces sudo to consume the password line even with cached tickets;
        # otherwise the root helper could read it as config candidate data.
        payload = password + "\n" + (stdin_data if stdin_data is not None else "")
        second = await self._run(target, f"sudo -k -S -p '' {fixed_command}", stdin_data=payload)
        if is_guard:
            logger.info(
                "vm_config_guard_sudo_stage",
                target=target, stage="sudo_password_retry",
                ssh_user=settings.SSH_USERNAME.strip(),
                success=second.get("success") is True,
                exit_code=second.get("exit_code"),
            )
        return second

    async def config_guard_preflight(self, target: str) -> Dict[str, Any]:
        """Verify the fixed guard path without privilege or leaking VM output.

        POSIX `test -e` reports false for BOTH a missing file and a path
        whose parent cannot be traversed. Distinguish those states so the
        operator does not incorrectly reinstall a helper that already exists.
        Log only allowlisted diagnostic codes and numeric metadata; never
        stdout/stderr or candidate content.
        """
        self._validate_target(target)
        command = (
            "LC_ALL=C; p=/usr/local/sbin/aiops-config-guard; "
            "if [ ! -x /usr ] || [ ! -x /usr/local ]; then printf 'PARENT_INACCESSIBLE'; "
            "elif [ ! -d /usr/local/sbin ]; then printf 'PARENT_MISSING'; "
            "elif [ ! -x /usr/local/sbin ]; then printf 'PARENT_INACCESSIBLE'; "
            "elif [ -L \"$p\" ]; then printf 'SYMLINK'; "
            "elif [ ! -e \"$p\" ]; then printf 'MISSING'; "
            "elif [ ! -f \"$p\" ]; then printf 'NOT_REGULAR'; "
            "else printf 'PRESENT '; stat -c '%u %g %a' -- \"$p\"; fi"
        )
        observed = await self._run(target, command)
        raw_probe = str(observed.get("stdout") or "").strip()
        fields = raw_probe.split()
        code = raw_probe if raw_probe in {
            "MISSING", "SYMLINK", "NOT_REGULAR",
            "PARENT_MISSING", "PARENT_INACCESSIBLE",
        } else "PRESENT" if len(fields) == 4 and fields[0] == "PRESENT" else "UNKNOWN"
        states = {
            "MISSING": "config_guard_helper_missing",
            "SYMLINK": "config_guard_helper_symlink_refused",
            "NOT_REGULAR": "config_guard_helper_not_regular",
            "PARENT_MISSING": "config_guard_helper_parent_missing",
            "PARENT_INACCESSIBLE": "config_guard_helper_parent_inaccessible",
        }
        if observed.get("success") is not True:
            code = "SSH_FAILED"
            status = "config_guard_preflight_unavailable"
        elif code == "PRESENT":
            status = ("config_guard_helper_present"
                      if fields[1:] == ["0", "0", "750"]
                      else "config_guard_helper_unsafe_metadata")
        else:
            status = states.get(code, "config_guard_preflight_unavailable")
        success = status == "config_guard_helper_present"
        # Do not persist stdout/stderr, config contents, or sudo credentials.
        logger.info(
            "vm_config_guard_preflight_completed",
            target=target,
            helper="/usr/local/sbin/aiops-config-guard",
            probe=code,
            status=status,
            success=success,
            ssh_exit_code=observed.get("exit_code"),
            ssh_auth_mode=self._auth_mode(),
        )
        return {"success": success, "status": status}

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

    async def memory_diagnostics(self, target: str) -> Dict[str, Any]:
        """Bounded, read-only RAM breakdown and top RSS consumers.

        No remote Python, sudo, command arguments, memory dumps or environment
        variables. One snapshot cannot establish which process caused a spike.
        """
        command = (
            "LC_ALL=C; "
            "printf 'MEMORY_BEGIN\n'; "
            "awk '/^(MemTotal|MemAvailable|MemFree|Cached|Buffers|SReclaimable|SwapTotal|SwapFree):/ "
            "{print $1,$2}' /proc/meminfo; "
            "printf 'MEMORY_END\n'; "
            "printf 'PROCESS_BEGIN\n'; "
            "ps -eo pid=,ppid=,comm=,rss=,%mem= --sort=-rss | head -n 12; "
            "printf 'PROCESS_END\n'; "
            "printf 'PRESSURE_BEGIN\n'; "
            "if [ -r /proc/pressure/memory ]; then "
            "awk '/^some / {for(i=1;i<=NF;i++) if($i ~ /^avg10=/) print $i}' "
            "/proc/pressure/memory; fi; "
            "printf 'PRESSURE_END\n'"
        )
        result = await self._run(target, command)
        if result.get("success") is not True:
            return {"success": False, "target": target,
                    "error": "memory_diagnostics_command_failed"}
        lines = str(result.get("stdout") or "").splitlines()
        section = None
        kib = {}
        processes = []
        psi_avg10 = None
        allowed = {"MemTotal", "MemAvailable", "MemFree", "Cached", "Buffers",
                   "SReclaimable", "SwapTotal", "SwapFree"}
        for line in lines[:70]:
            word = line.strip()
            if word == "MEMORY_BEGIN": section = "memory"; continue
            if word == "MEMORY_END": section = None; continue
            if word == "PROCESS_BEGIN": section = "process"; continue
            if word == "PROCESS_END": section = None; continue
            if word == "PRESSURE_BEGIN": section = "pressure"; continue
            if word == "PRESSURE_END": section = None; continue
            fields = word.split()
            try:
                if section == "memory" and len(fields) == 2:
                    key = fields[0].removesuffix(":")
                    if key in allowed:
                        value = int(fields[1])
                        if 0 <= value <= 2**53: kib[key] = value
                elif section == "process" and len(fields) == 5 and len(processes) < 10:
                    pid, ppid, comm, rss, pct = fields
                    if not re.fullmatch(r"[a-zA-Z0-9@_.:+-]{1,80}", comm):
                        comm = "redacted_process"
                    row = {"pid": int(pid), "ppid": int(ppid),
                           "command": comm[:80], "rss_mb": round(int(rss) / 1024, 1),
                           "memory_percent": round(float(pct), 2)}
                    if (row["pid"] > 0 and row["ppid"] >= 0
                            and 0 <= row["rss_mb"] < 2**40
                            and 0 <= row["memory_percent"] <= 100):
                        processes.append(row)
                elif section == "pressure" and word.startswith("avg10="):
                    x = float(word.split("=", 1)[1])
                    if 0 <= x <= 100: psi_avg10 = round(x, 2)
            except (ValueError, OverflowError):
                continue
        total, available = kib.get("MemTotal"), kib.get("MemAvailable")
        if not total or available is None or available > total:
            return {"success": False, "target": target,
                    "error": "memory_diagnostics_invalid_meminfo"}
        swap_total = kib.get("SwapTotal")
        swap_free = kib.get("SwapFree")
        used_pct = round((total - available) * 100 / total, 2)
        return {
            "success": True, "target": target,
            "total_mb": round(total / 1024, 1),
            "available_mb": round(available / 1024, 1),
            "used_percent": used_pct,
            "cache_reclaimable_mb": round(
                (kib.get("Cached", 0) + kib.get("SReclaimable", 0)) / 1024, 1),
            "swap_used_mb": (
                round((swap_total - swap_free) / 1024, 1)
                if swap_total is not None and swap_free is not None
                   and 0 <= swap_free <= swap_total else None),
            "swap_total_mb": (
                round(swap_total / 1024, 1) if swap_total is not None else None),
            "psi_memory_some_avg10": psi_avg10,
            "top_processes": processes,
            "snapshot_only": True,
            "reason_cannot_be_proven_from_single_snapshot": True,
        }

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
        result = await self._run(target, (
            "LC_ALL=C; df -P -B1 2>/dev/null; printf '\\n__AIOPS_INODES__\\n'; "
            "df -Pi 2>/dev/null; printf '\\n__AIOPS_BLOCK_DEVICES__\\n'; "
            "if command -v lsblk >/dev/null 2>&1; then "
            "lsblk -b -P -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,RO 2>/dev/null; fi; "
            "printf '\\n__AIOPS_MOUNT_MODES__\\n'; "
            "if command -v findmnt >/dev/null 2>&1; then "
            "findmnt -rn -o TARGET,OPTIONS 2>/dev/null; fi"
        ))
        if not result.get("success"):
            return {"success": False, "target": target, "error": "disk_status_failed"}
        disk_text, _, remainder = str(result.get("stdout") or "").partition("__AIOPS_INODES__")
        inode_text, block_marker, block_tail = remainder.partition("__AIOPS_BLOCK_DEVICES__")
        block_text, mount_marker, mount_text = block_tail.partition("__AIOPS_MOUNT_MODES__")

        def parse_df(value: str) -> list[Dict[str, Any]]:
            rows: list[Dict[str, Any]] = []
            lines = [line for line in value.splitlines() if line.strip()]
            for line in lines[1:]:
                parts = line.split(None, 5)
                if len(parts) == 6:
                    rows.append({"filesystem": parts[0], "blocks": parts[1], "used": parts[2], "available": parts[3], "use_percent": parts[4], "mount": parts[5]})
            return rows
        filesystems = parse_df(disk_text)
        if not filesystems:
            return {"success": False, "target": target, "error": "disk_inventory_empty"}
        mount_modes = parse_mount_modes(mount_text) if mount_marker else {}
        for row in filesystems:
            row["read_only"] = mount_modes.get(row["mount"])
        devices = parse_block_devices(block_text) if block_marker else []
        return {"success": True, "target": target, "filesystems": filesystems,
                "block_devices": devices,
                "block_devices_supported": bool(block_marker and block_text.strip()),
                "mount_read_only_supported": bool(mount_marker and mount_text.strip()),
                "inodes": parse_df(inode_text),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "source": self.source_name}

    async def disk_forensics(self, target: str) -> Dict[str, Any]:
        """Bounded read-only inventory; never read file contents or delete files.

        The scanner only inspects mounted filesystem roots taken from df, not
        LLM/alert-supplied paths. It skips virtual mounts and is time limited.
        Results are hints for cross-source causality, not deletion approval.
        """
        # Includes size, inode pressure, mount point; stderr is not returned.
        inventory = await self.disk_status(target)
        if not inventory.get("success"):
            return {"success": False, "target": target, "error": "disk_inventory_failed"}
        from domain.contracts.redaction import redact_text
        candidates = []
        for row in inventory.get("filesystems") or []:
            try:
                used = int(str(row.get("use_percent") or "").rstrip("%"))
                mount = str(row.get("mount") or "")
                if used < 80 or not (mount == "/" or mount.startswith("/")):
                    continue
                if mount.startswith(("/proc", "/sys", "/dev", "/run", "/snap")):
                    continue
                if mount != "/" and (not re.fullmatch(r"/[A-Za-z0-9_./+-]{1,180}", mount)
                                     or ".." in mount.split("/")):
                    continue
                candidates.append((used, mount))
            except (ValueError, TypeError):
                continue
        candidates.sort(reverse=True)
        selected = []
        for used, mount in candidates[:2]:
            # Scanning the full / tree can be costly: use bounded high-value
            # directories on root, and the explicit df mount for other disks.
            roots = ["/var/log", "/var/lib", "/opt", "/tmp"] if mount == "/" else [mount]
            # Quote only paths obtained from df and accepted by the strict
            # whitelist; no arbitrary commands or filenames enter the shell.
            roots = [root for root in roots if re.fullmatch(r"/[A-Za-z0-9_./+-]{1,180}", root)]
            if not roots:
                continue
            command = (
                "LC_ALL=C timeout 12s find " + " ".join(shlex.quote(root) for root in roots)
                + " -xdev -type f -size +20M -printf '%s\\t%T@\\t%p\\n' 2>/dev/null"
                + " | sort -nr | head -n 25"
            )
            output = await self._run(target, command)
            files = []
            if output.get("success"):
                for line in str(output.get("stdout") or "").splitlines()[:25]:
                    parts = line.split("\t", 2)
                    if len(parts) != 3:
                        continue
                    try:
                        size = int(parts[0])
                        changed = float(parts[1])
                        path = parts[2]
                    except (TypeError, ValueError):
                        continue
                    if size < 20 * 1024 * 1024 or not path.startswith("/"):
                        continue
                    # A path may contain control chars; only return safe,
                    # bounded paths, and never include file contents.
                    if len(path) > 300 or any(ord(ch) < 32 for ch in path):
                        continue
                    files.append({"path": redact_text(path), "size_bytes": size,
                                  "mtime_epoch": changed,
                                  "owner_service": None, "growth_confirmed": False,
                                  "retention_policy_verified": False})
            # A second metadata sample and open-FD lookup help distinguish
            # active growth from an old/static file. Never open file contents.
            # Limit to four files per mount, one bounded extra SSH roundtrip.
            if files:
                selected_files = files[:4]
                paths = " ".join(shlex.quote(item["path"]) for item in selected_files)
                stat_cmd = "LC_ALL=C stat --printf='%i\\t%s\\t%n\\n' -- " + paths + " 2>/dev/null"
                watch_cmd = (
                    stat_cmd + "; printf '\\n__AIOPS_STAT_SECOND__\\n'; sleep 2; "
                    + stat_cmd + "; printf '\\n__AIOPS_LSOF__\\n'; "
                    + "if command -v lsof >/dev/null 2>&1; then "
                    + "timeout 3s lsof -nP -Fpcfn -- " + paths
                    + " 2>/dev/null | head -n 80; fi"
                )
                observed = await self._run(target, watch_cmd)
                if observed.get("success"):
                    first_text, marker, tail = str(observed.get("stdout") or "").partition(
                        "__AIOPS_STAT_SECOND__"
                    )
                    second_text, lsof_marker, open_text = tail.partition("__AIOPS_LSOF__")
                    def parse_stats(value: str) -> dict[str, tuple[int, int]]:
                        result: dict[str, tuple[int, int]] = {}
                        for line in value.splitlines()[:8]:
                            fields = line.split("\t", 2)
                            if len(fields) != 3:
                                continue
                            try:
                                result[fields[2]] = (int(fields[0]), int(fields[1]))
                            except (TypeError, ValueError):
                                continue
                        return result

                    if marker:
                        first, second = parse_stats(first_text), parse_stats(second_text)
                        for item in selected_files:
                            before, after = first.get(item["path"]), second.get(item["path"])
                            if not before or not after or before[0] != after[0]:
                                continue
                            item["growth_measured"] = True
                            item["growth_bytes_over_2_seconds"] = max(after[1] - before[1], 0)
                            item["growth_confirmed"] = after[1] > before[1]
                    if lsof_marker:
                        pid = None
                        command_name = None
                        fd = None
                        selected_by_path = {item["path"]: item for item in selected_files}
                        for line in open_text.splitlines()[:80]:
                            if len(line) < 2:
                                continue
                            tag, value = line[0], line[1:]
                            if tag == "p" and value.isdigit():
                                pid = int(value)
                                command_name, fd = None, None
                            elif tag == "c":
                                command_name = redact_text(value[:90])
                            elif tag == "f":
                                fd = value[:30]
                            elif tag == "n" and value in selected_by_path and pid is not None:
                                item = selected_by_path[value]
                                item.setdefault("open_handles", [])
                                if len(item["open_handles"]) < 5:
                                    item["open_handles"].append({
                                        "pid": pid, "process_name": command_name,
                                        "file_descriptor": fd,
                                        "writable_handle_observed": bool(
                                            fd and ("w" in fd or "u" in fd)
                                        ),
                                        "writer_causality_verified": False,
                                    })
            selected.append({"mount": mount, "used_percent": used,
                             "files": files, "scan_success": bool(output.get("success")),
                             "scan_scope": roots, "scan_complete_verified": False})
        return {
            "success": True, "target": target,
            "diagnostic": "disk_forensics",
            "mounts": selected, "files_examined": sum(len(x["files"]) for x in selected),
            "delete_authorized": False, "file_age_proves_safe_to_delete": False,
            "growth_measured": any(
                file.get("growth_measured") is True
                for mount in selected for file in mount["files"]
            ), "content_inspected": False,
            "limitations": [
                "Short two-point samples do not establish historical growth or root cause; absent growth does not prove a static file",
                "Open file handles do not prove which process originally wrote a file",
                "Other mountpoints and small files may be unexamined",
                "Elastic/Zabbix temporal correlation and retention policy are required before proposing cleanup",
            ],
        }

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

    async def list_services(self, target: str, state: str | None = None,
                            query: str | None = None, limit: int = 250) -> Dict[str, Any]:
        """Fixed read-only systemctl inventory; display only policy-visible units."""
        self._validate_target(target)
        if state not in (None, "failed"):
            raise ValueError("invalid_service_state_filter")
        if query is not None and (not isinstance(query, str) or not query.strip()
                                  or len(query) > 80 or any(ord(c) < 32 for c in query)):
            raise ValueError("invalid_service_search_query")
        limit = min(max(int(limit), 1), 500)
        observed = await self._run(
            target,
            "LC_ALL=C systemctl list-units --type=service --all --no-pager --plain --full --no-legend",
        )
        if observed.get("success") is not True:
            return {"success": False, "target": target, "services": [],
                    "error": "service_inventory_command_failed"}
        configured = (settings.VM_AGENT_ALLOWED_SERVICES if self.source_name == "vm_agent"
                      else settings.SSH_ALLOWED_SERVICES)
        allowed = {str(service).strip() for service in configured if str(service).strip()}
        parsed = parse_systemd_services(str(observed.get("stdout") or ""),
                                        allowed_services=allowed if allowed else None,
                                        state=state, query=query, limit=limit)
        for unit in parsed["services"]:
            unit["description"] = redact_text(unit["description"])
        return {"success": True, "target": target, **parsed,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "source": self.source_name}

    async def search_services(self, target: str, query: str,
                              state: str | None = None, limit: int = 250) -> Dict[str, Any]:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("invalid_service_search_query")
        return await self.list_services(target, query=query, state=state, limit=limit)

    async def service_status(self, target: str, service: str) -> Dict[str, Any]:
        """Read structured systemd properties and bounded 'systemctl status'.

        Failed/inactive units can make `systemctl status` exit 3; this is a
        diagnostic observation, not an SSH failure. Never use arbitrary shell
        commands supplied by an agent or HTTP request.
        """
        self._validate_service(service)
        props = " --property=".join([
            "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID",
            "ExecMainCode", "ExecMainStatus", "NRestarts", "Result",
            "TimeoutStartUSec", "TimeoutStopUSec",
        ])
        result = await self._run(target, f"systemctl show --no-pager --property={props} {service}")
        if not result.get("success"):
            return {
                "success": False, "target": target, "service": service,
                "status": "unknown", "error": "service_status_failed",
                "detail": str(result.get("stderr") or result.get("error") or "")[:500],
            }
        values: Dict[str, str] = {}
        for line in str(result.get("stdout") or "").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value

        def numeric(field: str) -> int | None:
            value = values.get(field, "")
            try:
                return int(value) if value else None
            except ValueError:
                return None

        active_state = values.get("ActiveState", "unknown")
        diagnostics: Dict[str, Any] = {
            "success": True, "target": target, "service": service,
            # Id is systemd's canonical loaded unit, unlike a requested alias.
            # The Control Plane must check it independently before binding.
            "unit_id": str(values.get("Id") or "")[:128] or None,
            "load_state": values.get("LoadState"), "active_state": active_state,
            "sub_state": values.get("SubState"), "unit_file_state": values.get("UnitFileState"),
            "main_pid": numeric("MainPID"), "exec_main_code": numeric("ExecMainCode"),
            "exec_main_status": numeric("ExecMainStatus"),
            "restart_count": numeric("NRestarts"), "result": values.get("Result"),
            "timeout_start_usec": values.get("TimeoutStartUSec"),
            "timeout_stop_usec": values.get("TimeoutStopUSec"),
            # systemd ActiveState can be transient during crash/restart loops.
            # It proves neither a successful application startup nor HTTP health.
            "status": active_state, "systemd_active": active_state == "active",
            "healthy": None, "application_health_verified": False, "error": None,
        }
        if active_state in {"failed", "inactive", "activating", "deactivating"}:
            status = await self._run(
                target, f"LC_ALL=C systemctl status {service} --no-pager -l --lines=30"
            )
            # 3 means an inactive/failed service; preserve its status output.
            if status.get("success") or status.get("exit_code") == 3:
                diagnostics["systemctl_status"] = redact_text(str(status.get("stdout") or "")[:12000])
                diagnostics["systemctl_status_exit_code"] = status.get("exit_code")
            else:
                diagnostics["systemctl_status"] = None
                diagnostics["systemctl_status_error"] = str(
                    status.get("stderr") or status.get("error") or "status_command_failed"
                )[:500]
        return diagnostics

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

    async def service_logs(self, target: str, service: str, limit: int = 150) -> Dict[str, Any]:
        """Collect bounded journald history; retry read-only via sudo -n if denied.

        A narrowly scoped NOPASSWD journalctl permission is provisioned by the
        VM owner, never by AIOps. A failed attempt remains an error observation.
        """
        self._validate_service(service)
        bounded = self._bounded_limit(limit)
        command = f"journalctl --no-pager -u {service} -n {bounded} -o short-iso"
        result = await self._run(target, command)
        mode = "user"
        if not result.get("success"):
            failure = str(result.get("stderr") or "") + " " + str(result.get("stdout") or "")
            if any(word in failure.lower() for word in ("permission", "access denied", "not permitted", "insufficient")):
                mode = "sudo"
                result = await self._sudo(target, command)
        if not result.get("success"):
            detail = str(result.get("stderr") or result.get("error") or "journalctl_failed")
            return {
                "success": False, "target": target, "service": service,
                "logs": [], "error": "journal_access_denied" if mode == "sudo" else "service_logs_failed",
                "access_mode": mode, "exit_code": result.get("exit_code"),
                "detail": detail[:500],
            }
        lines = [redact_text(line[:1200]) for line in str(result.get("stdout") or "").splitlines() if line.strip()]
        return {
            "success": True, "target": target, "service": service,
            "logs": lines[-bounded:], "count": len(lines[-bounded:]), "access_mode": mode,
        }

    async def system_logs(self, target: str, limit: int = 100) -> Dict[str, Any]:
        bounded = self._bounded_limit(limit)
        command = f"journalctl --no-pager -n {bounded} -o short-iso"
        result = await self._run(target, command)
        mode = "user"
        if not result.get("success"):
            failure = (str(result.get("stderr") or "") + " " + str(result.get("stdout") or "")).lower()
            if any(word in failure for word in ("permission", "access denied", "not permitted", "insufficient")):
                mode = "sudo"
                result = await self._sudo(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "logs": [], "error": "system_logs_failed",
                    "access_mode": mode, "detail": str(result.get("stderr") or result.get("error") or "")[:500]}
        lines = [redact_text(line[:1200]) for line in str(result.get("stdout") or "").splitlines() if line.strip()]
        return {"success": True, "target": target, "logs": lines[-bounded:], "count": len(lines[-bounded:]), "access_mode": mode}

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

    async def service_runtime_discovery(self, target: str, service: str) -> Dict[str, Any]:
        """Read selected systemd properties; never return ExecStart argv or env values."""
        self._validate_service(service)
        result = await self._run(
            target,
            "systemctl show --no-pager "
            "--property=ExecStart,WorkingDirectory,FragmentPath,Type,TimeoutStartUSec,Restart "
            + shlex.quote(service),
        )
        if not result.get("success"):
            return {
                "success": False, "target": target, "service": service,
                "runtime": "unknown", "error": "runtime_discovery_unavailable",
            }
        parsed = parse_systemd_runtime(str(result.get("stdout") or ""), service=service)
        return {"success": True, "target": target, **parsed}

    async def service_config_discovery(self, target: str, service: str) -> Dict[str, Any]:
        """Read-only proof of config-path existence from systemd-derived paths.

        No arbitrary LLM path is read. No config values/argv/environment leave
        this VM MCP edge. This is existence, NOT content or syntax validation.
        """
        self._validate_service(service)
        unit = await self.service_runtime_discovery(target, service)
        base = {
            "success": unit.get("success") is True, "target": target,
            "service": service, "runtime": unit.get("runtime", "unknown"),
            "unit_file": unit.get("unit_file"),
            "config_contents_exposed": False, "environment_values_read": False,
            "read_only": True, "execution_authority": False,
            "files": [], "recommended_next_check": "consult_llm_for_unknown_configuration",
        }
        if not unit.get("success"):
            return {**base, "status": "systemd_unavailable"}
        from integrations.vm.runtime_discovery import _candidate_path
        paths = list((unit.get("config_candidates") or [])[:10])
        # For a validated .NET ExecStart DLL, its publish directory is a
        # systemd-derived configuration root even if WorkingDirectory is unset.
        # Probe the known .NET filename for existence ONLY, never content.
        if unit.get("runtime") == "dotnet":
            from integrations.vm.runtime_discovery import safe_absolute_path
            publish = safe_absolute_path(unit.get("publish_directory"))
            if (publish and publish.startswith(("/opt/", "/srv/", "/data/"))
                    and len(publish.strip("/").split("/")) >= 2):
                appsettings = _candidate_path(publish.rstrip("/") + "/appsettings.json")
                if appsettings and all(
                    not isinstance(c, dict) or c.get("path") != appsettings for c in paths
                ):
                    paths.append({"path": appsettings, "source": "systemd_dotnet_publish"})
        for candidate in paths:
            if not isinstance(candidate, dict):
                continue
            path = _candidate_path(candidate.get("path"))
            if not path:
                continue
            quoted = shlex.quote(path)
            command = (
                "test -f " + quoted + " && test -r " + quoted
                + " && test ! -L " + quoted
                + " && test \"$(readlink -f -- " + quoted + ")\" = " + quoted
            )
            try:
                result = await self._run(target, command)
            except Exception:
                result = {"success": False}
            base["files"].append({
                "path": path, "source": str(candidate.get("source") or "systemd")[:45],
                "status": "exists_readable" if result.get("success") else "not_verified",
                "verified_exists": result.get("success") is True,
                "content_validated": False,
            })
        # If systemd has no explicit config flags, inspect ONLY the
        # unit-owned working directory, never a path suggested by an LLM.
        # Inventory returns filenames, not file contents or environment.
        if not any(item["verified_exists"] for item in base["files"]):
            from integrations.vm.runtime_discovery import safe_absolute_path, _candidate_path
            working = safe_absolute_path(unit.get("working_directory"))
            if (working and len(working) <= 210
                    and working.startswith(("/opt/", "/srv/", "/data/", "/usr/local/etc/"))
                    and len(working.strip("/").split("/")) >= 2):
                q = shlex.quote(working)
                inventory_command = (
                    "test -d " + q + " && test ! -L " + q
                    + " && test \"$(readlink -f -- " + q + ")\" = " + q
                    + " && LC_ALL=C find " + q
                    + " -mindepth 1 -maxdepth 2 -type f "
                    + "\\( -name '*.conf' -o -name '*.cfg' -o -name '*.xml' "
                    + "-o -name '*.properties' -o -name '*.yaml' -o -name '*.yml' "
                    + "-o -name '*.json' -o -name '*.ini' -o -name '*.toml' "
                    + "-o -name '*.hcl' -o -name '*.cnf' -o -name '*.config' \\)"
                    + " -print 2>/dev/null | head -n 24"
                )
                try:
                    inventory = await self._run(target, inventory_command)
                except Exception:
                    inventory = {"success": False}
                if inventory.get("success"):
                    existing = {x["path"] for x in base["files"]}
                    for path in str(inventory.get("stdout") or "").splitlines()[:24]:
                        safe = _candidate_path(path)
                        if (not safe or safe in existing or
                                not safe.startswith(working.rstrip("/") + "/") or
                                any(word in safe.lower() for word in (
                                    "secret", "credential", "password", "private", ".key",
                                ))):
                            continue
                        # Verify each returned entry. A name from a
                        # directory listing is not proof of read permission.
                        candidate = shlex.quote(safe)
                        probe = await self._run(
                            target, "test -f " + candidate + " && test -r " + candidate
                            + " && test ! -L " + candidate
                            + " && test \"$(readlink -f -- " + candidate + ")\" = " + candidate,
                        )
                        existing.add(safe)
                        base["files"].append({
                            "path": safe, "source": "systemd_working_directory_inventory",
                            "status": "exists_readable" if probe.get("success") else "not_verified",
                            "verified_exists": probe.get("success") is True,
                            "content_validated": False,
                        })
                        if len(base["files"]) >= 16:
                            break
        base["status"] = ("verified_candidates" if any(
            item["verified_exists"] for item in base["files"]) else
            "candidates_not_verified" if base["files"] else "no_systemd_config_candidates")
        return base

    async def dependency_investigation(self, target: str, service: str) -> Dict[str, Any]:
        from integrations.vm.dependency_investigation import investigate
        return await investigate(self, target, service)

    async def redis_dependency_check(self, target: str, service: str) -> Dict[str, Any]:
        """Read-only Redis endpoint verification from a trusted systemd appsettings file."""
        from integrations.vm.redis_dependency import check_redis_config
        return await check_redis_config(self, target, service)

    async def service_config_llm_repair(self, target: str, service: str) -> Dict[str, Any]:
        """Operator-requested full-file LLM repair, read-only and not approvable.

        The source is never returned in an MCP response. Only the trusted VM
        worker sees the SSH bytes; only its configured LLM gateway receives
        the complete document, when explicitly enabled by the operator.
        """
        self._validate_target(target)
        self._validate_service(service)
        from domain.contracts.config import settings
        from integrations.vm.general_config_review import (
            checked_config_path, remote_config_read_command,
        )
        from integrations.vm.full_config_llm_repair import review_complete_config
        base = {
            "success": True, "target": target, "service": service,
            "status": "file_not_verified", "validation_status": "UNVERIFIED",
            "apply_eligible": False, "execution_authority": False,
            "config_contents_exposed": False,
            "llm_received_complete_file": False,
            "llm_returned_complete_file": False,
        }
        if not settings.AIOPS_FULL_CONFIG_LLM_ENABLED:
            return {**base, "status": "full_config_llm_not_enabled"}
        validator = await self.config_validate(target, service)
        discovered = await self.service_config_discovery(target, service)
        candidates = []
        # Validator and systemd, never alert text or an LLM-supplied path.
        if validator.get("supported") and validator.get("config_file"):
            candidates.append(validator["config_file"])
        for item in (discovered.get("files") or [])[:20]:
            if isinstance(item, dict) and item.get("verified_exists") is True:
                candidates.append(item.get("path"))
        # For the .NET endpoint, a discovered appsettings.json is the primary
        # application config. Do not blindly send unrelated JSON data files
        # (e.g. MessageTemplates.json) to an LLM just because the first read
        # succeeded. All paths here MUST already be existence-verified by VM
        # discovery or registered vendor validation.
        if str(discovered.get("runtime") or "").lower() == "dotnet":
            primary = [
                p for p in candidates
                if isinstance(p, str) and (
                    p.rsplit("/", 1)[-1] == "appsettings.json"
                    or (p.rsplit("/", 1)[-1].startswith("appsettings.")
                        and p.endswith(".json"))
                )
            ]
            if primary:
                candidates = primary
        had_read_failure = False
        for path in list(dict.fromkeys(candidates))[:12]:
            try:
                safe = checked_config_path(path)
                command = remote_config_read_command(safe)
            except (ValueError, TypeError):
                continue
            read = await self._run(target, command)
            if not read.get("success"):
                had_read_failure = True
                continue
            output = await review_complete_config(
                str(read.get("stdout") or ""), path=safe, service=service,
                vendor_error=(str(validator.get("syntax_error") or "")[:900]
                              if safe == validator.get("config_file") else ""), target=target,
            )
            return {**base, **output, "target": target, "service": service,
                    "selected_by": (
                        "verified_dotnet_appsettings" if str(
                            discovered.get("runtime") or "").lower() == "dotnet"
                        else "verified_service_config_discovery"
                    )}
        return {
            **base, "status": ("file_read_unavailable" if had_read_failure
                                else "file_not_verified")
        }

    async def service_config_review(self, target: str, service: str) -> Dict[str, Any]:
        """Read-only bounded review for a vendor error or verified unit file.

        Never accepts a model-supplied path; no source configuration bytes
        cross the VM MCP API. JSON candidate previews have no write authority.
        """
        self._validate_service(service)
        from integrations.vm.general_config_review import (
            checked_config_path, remote_config_read_command, local_config_review,
        )
        base = {
            "success": True, "target": target, "service": service,
            "status": "file_not_verified", "execution_authority": False,
            "apply_eligible": False, "config_contents_exposed": False,
        }
        validator = await self.config_validate(target, service)
        discovered = await self.service_config_discovery(target, service)
        known = []
        if (validator.get("success") is True
                and validator.get("supported") is True
                and validator.get("valid") is False
                and validator.get("config_file")):
            known.append((validator["config_file"], "confirmed_vendor_validator",
                          validator.get("error_line")))
        for row in (discovered.get("files") or [])[:10]:
            if isinstance(row, dict) and row.get("verified_exists") is True:
                known.append((row.get("path"), "verified_systemd_candidate", None))
        # An application may own many JSON/XML/config files. Inspect
        # systemd/validator-verified candidates in order, preferring one
        # with a deterministic repair rather than blindly stopping at the
        # first readable (possibly healthy) file.
        outcome = None
        selected = None
        read_failed = False
        reviewed_files = []
        visited = set()
        for path, path_source, error_line in known[:16]:
            if path in visited:
                continue
            visited.add(path)
            try:
                command = remote_config_read_command(checked_config_path(path))
            except (ValueError, TypeError):
                continue
            response = await self._run(target, command)
            if not response.get("success"):
                read_failed = True
                continue
            candidate = local_config_review(
                str(response.get("stdout") or ""), path=path,
                validator_error_line=error_line,
                vendor_service=(service if path == validator.get("config_file")
                                and validator.get("valid") is False else ""),
                vendor_error=str(validator.get("syntax_error") or "")[:600],
                syntax_profile=(
                    "dotnet_jsonc" if str(discovered.get("runtime") or "").lower() == "dotnet"
                    and path.rsplit("/", 1)[-1] == "appsettings.json"
                    else "strict_json"
                ),
            )
            reviewed_files.append({
                "path": path, "path_source": path_source,
                "file_type": candidate.get("file_type"),
                "status": candidate.get("status"),
                "validation_status": candidate.get("validation_status"),
                "syntax_projection": candidate.get("syntax_projection"),
                "candidate_syntax_projection": candidate.get("candidate_syntax_projection"),
                "observed_error_line": candidate.get("observed_error_line"),
            })
            if outcome is None:
                outcome = candidate
                selected = (path, path_source)
            # Do not show the FIRST syntactically healthy JSON file while a
            # later systemd-verified appsettings.json is actually broken.
            # A measured syntax failure outranks a healthy/unverified review.
            if (candidate.get("validation_status") == "FORMAT_INVALID"
                    and outcome.get("status") != "candidate_proposed"):
                outcome = candidate
                selected = (path, path_source)
            # A confirmed broken application entrypoint config outranks any
            # patchable unrelated JSON data file. Otherwise we could offer an
            # Approval for MessageTemplates.json while appsettings.json stays
            # syntactically invalid. This priority is derived from the runtime
            # and verified path, never from an LLM-supplied path.
            primary_dotnet_appsettings = (
                str(discovered.get("runtime") or "").lower() == "dotnet"
                and path.rsplit("/", 1)[-1] == "appsettings.json"
                and candidate.get("validation_status") in {
                    "FORMAT_INVALID", "FORMAT_CANDIDATE_VALID_ONLY",
                }
            )
            if primary_dotnet_appsettings or (
                path_source == "confirmed_vendor_validator"
                and candidate.get("validation_status") == "FORMAT_INVALID"
            ):
                outcome = candidate
                selected = (path, path_source)
                break
            if candidate.get("status") == "candidate_proposed":
                outcome = candidate
                selected = (path, path_source)
                break
        if outcome is None or selected is None:
            return {
                **base,
                "status": "file_read_unavailable" if read_failed else "file_not_verified",
                "discovery_status": discovered.get("status") or "unavailable",
                "recommended_next_check": (
                    "check_scoped_read_permissions" if read_failed
                    else "llm_vendor_documentation_and_systemd_audit"
                ),
            }
        path, source = selected
        # No config contents, values, redacted excerpts or hashes in logs.
        # Earlier MCP responses exceeded the HTTP log size limit and hid
        # why Approval generation stopped, making every retry opaque.
        logger.info(
            "service_config_candidate_diagnostic",
            service=service,
            file_type=str(outcome.get("file_type") or "unknown")[:20],
            review_status=str(outcome.get("status") or "unknown")[:65],
            format_status=str(outcome.get("validation_status") or "unknown")[:65],
            repair_blocker=str(outcome.get("repair_blocker") or "none")[:100],
            parser_error_line=outcome.get("observed_error_line"),
            proposed_change=str(outcome.get("proposed_change") or "none")[:65],
            candidate_hash_present=bool(outcome.get("candidate_hash")),
            verified_file_count=len(reviewed_files),
        )
        return {
            **base, **outcome, "target": target, "service": service,
            "path_source": source,
            "reviewed_file_count": len(reviewed_files),
            "file_reviews": reviewed_files[:12],
            "vendor_validation": (
                "invalid" if validator.get("valid") is False
                and validator.get("success") is True else
                "valid" if validator.get("valid") is True
                and validator.get("success") is True else "unavailable"
            ),
            "execution_authority": False, "apply_eligible": False,
            "config_contents_exposed": False,
        }

    async def dotnet_config_syntax(self, target: str, service: str) -> Dict[str, Any]:
        """Remote Linux coreutils read; *local AIOps Python* JSON syntax check.

        No python, SDK or additional binaries are installed on the VM. Config
        bytes traverse authenticated SSH only to this trusted AIOps VM connector.
        They NEVER enter returned tool results, logs, DB, HTTP API or LLM prompt.
        """
        discovery = await self.service_runtime_discovery(target, service)
        base = {
            "target": target, "service": service, "runtime": discovery.get("runtime"),
            "publish_directory": discovery.get("publish_directory"),
            "environment_values_read": False, "config_contents_exposed": False,
            "validator": "aiops-local-python-json-syntax-only",
            "remote_python_required": False,
            "config_values_persisted": False,
            "validated_scope": "json_syntax_only",
            "application_ready": None, "configuration_semantics_valid": None,
        }
        if not discovery.get("success") or discovery.get("runtime") != "dotnet":
            return {**base, "success": True, "supported": False,
                    "syntax_valid": None, "status": "runtime_not_verified"}
        directory = discovery["publish_directory"]
        try:
            listing = await self._run(target, remote_file_listing_command(directory))
        except (ValueError, TypeError):
            return {**base, "success": False, "supported": False,
                    "syntax_valid": None, "status": "unsafe_publish_directory"}
        if not listing.get("success"):
            return {**base, "success": False, "supported": False,
                    "syntax_valid": None, "status": "config_inventory_unavailable"}
        names, incomplete = safe_json_files(str(listing.get("stdout") or "")[:120000])
        if not names:
            return {**base, "success": True, "supported": False,
                    "syntax_valid": None, "status": "partial" if incomplete else "not_found",
                    "files": []}
        rows = []
        for name in names[:MAX_FILES]:
            try:
                fetched = await self._run(target, remote_file_read_command(directory, name))
            except ValueError:
                fetched = {"success": False}
            if not fetched.get("success"):
                rows.append({"file": name, "status": "unavailable",
                             "reason": "file_not_readable_or_oversized"})
                incomplete = True
                continue
            # IMPORTANT: 'stdout' is encoded config containing secrets.
            # Do NOT log, redact into a persisted artifact, or return it.
            # A bounded decoder parses entirely on the AIOps worker.
            row = validate_encoded_file(name, str(fetched.get("stdout") or ""))
            rows.append(row)
            if row["status"] == "unavailable":
                incomplete = True
        failures = any(item.get("status") == "invalid_json_syntax" for item in rows)
        final_status = "invalid" if failures else "partial" if incomplete else "syntax_valid"
        return {
            **base, "success": True, "supported": True,
            "syntax_valid": False if failures else None if incomplete else True,
            "status": final_status, "files": rows,
        }

    async def nginx_config_inspect(self, target: str, service: str) -> Dict[str, Any]:
        """Inspect only allowlisted Nginx config structure; no raw file bytes.

        The VM OS account must already have read access. No arbitrary sudo or
        user/model-supplied file path is accepted.
        """
        self._validate_service(service)
        if str(service).lower().removesuffix(".service") != "nginx":
            return {
                "success": False, "supported": False, "target": target,
                "service": service, "status": "unsupported_service",
                "execution_authority": False,
            }
        validator = await self.config_validate(target, service)
        syntax_status = (
            "valid" if validator.get("success") and validator.get("supported") and validator.get("valid") is True else
            "invalid" if validator.get("success") and validator.get("supported") and validator.get("valid") is False else
            "unverified"
        )
        # Compiler-derived paths only. nginx -t may identify an included
        # site file, even when ExecStartPre prevents the service from starting.
        error_file = validator.get("config_file") if syntax_status == "invalid" else None
        error_line = validator.get("error_line") if syntax_status == "invalid" else None
        inspected = await self._run(
            target, nginx_inspection_command(error_file, error_line),
        )
        base = {
            "target": target, "service": service, "supported": True,
            "read_only": True, "execution_authority": False,
            "validator_status": syntax_status,
            "validator_error_file": error_file,
            "validator_error_line": error_line,
            "validator_error": str(validator.get("syntax_error") or "")[:350],
            "root_config_file": validator.get("root_config_file"),
        }
        if not inspected.get("success"):
            return {
                **base, "success": False, "status": "ssh_or_inspection_unavailable",
                "files": [], "config_contents_exposed": False,
                "line_values_exposed": False,
            }
        result = parse_nginx_inspection(inspected.get("stdout") or "")
        return {
            **base, **result, "success": result.get("status") in {"inspected", "partial"},
        }

    async def nginx_config_review(self, target: str, service: str) -> Dict[str, Any]:
        """Generate a non-executable, bounded review from current validator proof."""
        self._validate_service(service)
        if service.lower() not in {"nginx", "nginx.service"}:
            return {
                "success": True, "supported": False, "target": target,
                "service": service, "status": "unsupported_service",
                "validation_status": "UNVERIFIED", "execution_authority": False,
            }
        validator = await self.config_validate(target, service)
        base = {
            "target": target, "service": service, "success": True,
            "supported": False, "status": "not_applicable",
            "validation_status": "UNVERIFIED", "execution_authority": False,
            "config_contents_exposed": False,
        }
        if not (validator.get("success") is True and validator.get("supported") is True
                and validator.get("valid") is False):
            return {**base, "status": "no_confirmed_syntax_failure"}
        # Even when the bounded remote read is denied, return the exact
        # compiler-proven file/line so UI can explain *why* no candidate
        # exists instead of collapsing to the misleading not_recorded.
        base.update({
            "config_file": validator.get("config_file"),
            "error_line": validator.get("error_line"),
            "syntax_error": str(validator.get("syntax_error") or "")[:280],
            "remote_python_required": False,
        })
        try:
            command = nginx_review_command(
                validator.get("config_file"),
                validator.get("error_line"),
                validator.get("syntax_error") or validator.get("detail") or "",
            )
        except ValueError:
            return {**base, "status": "unsafe_or_unknown_error_location"}
        # The remote endpoint has no Python requirement. Encoded source
        # bytes stay in this VM MCP worker process; never return/log them.
        response = await self._run(target, command)
        if not response.get("success"):
            return {
                **base, "status": "preview_unavailable",
                "remote_python_required": False,
            }
        raw = local_nginx_review(
            encoded=str(response.get("stdout") or ""),
            file_path=str(validator.get("config_file")),
            error_line=validator.get("error_line"),
            syntax_error=str(validator.get("syntax_error") or validator.get("detail") or ""),
        )
        if raw.get("status") not in {"observed", "candidate_proposed"}:
            return {
                **base, "status": "preview_unavailable",
                "remote_python_required": False,
            }
        # No raw configuration or arbitrary tool-returned keys cross the MCP.
        structure = re.compile(
            r"(?:[A-Za-z_][A-Za-z0-9_]{0,40}(?: \[arguments redacted\])?"
            r"(?: [{}]{1,8})?|\[structural\](?: [{}]{1,8})?"
            r"|\[blank or comment\]|\[remove entire stray brace line\])"
        )
        def safe_preview_text(value: Any) -> str:
            text = str(value or "")[:125]
            return text if structure.fullmatch(text) else "[unavailable/redacted]"
        def safe_rows(rows: Any) -> list[dict]:
            return [
                {"line": row["line"], "content": safe_preview_text(row.get("content"))}
                for row in (rows if isinstance(rows, list) else [])[:7]
                if isinstance(row, dict) and type(row.get("line")) is int
            ]
        digest = lambda key: str(raw.get(key)) if isinstance(raw.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", raw[key]) else None
        diff = raw.get("diff") if isinstance(raw.get("diff"), dict) else {}
        return {
            **base, "supported": True,
            "status": raw["status"],
            "config_file": validator.get("config_file"),
            "error_line": validator.get("error_line"),
            "syntax_error": str(validator.get("syntax_error") or "")[:280],
            "current_hash": digest("current_hash"),
            "candidate_hash": digest("candidate_hash"),
            "current_excerpt": safe_rows(raw.get("current_excerpt")),
            "proposed_excerpt": safe_rows(raw.get("proposed_excerpt")),
            "diff": {
                "line": diff.get("line") if type(diff.get("line")) is int else None,
                "before": safe_preview_text(diff.get("before")),
                "after": safe_preview_text(diff.get("after")),
                "redacted": True,
            } if diff else None,
            "proposed_change": "remove_extra_opening_brace" if raw.get("proposed_change") == "remove_extra_opening_brace" else None,
            "validation_status": "UNVERIFIED",
            "stage_failure_reason": "isolated_validation_not_available",
            "validator_executed_on_proposal": False,
            "test_scope": "worker_preview_unvalidated",
            "remote_python_required": False,
            "config_contents_exposed": False,
            "execution_authority": False, "apply_eligible": False,
            "requires_approval": True,
        }

    async def config_validate(self, target: str, service: str) -> Dict[str, Any]:
        """Locate the running unit's config, run a fixed read-only syntax check.

        The LLM cannot supply paths or commands. Syntax errors are extracted
        from the validator's own output, not inferred from model prose.
        """
        self._validate_service(service)
        adapter = get_service_adapter(service)
        # Read ONLY the unit's metadata. For an unknown allowlisted service,
        # expose a potential config path for the LLM advisory to reason about,
        # but never run LLM-generated scripts or label this path validated.
        meta = await self._run(
            target, f"systemctl show --no-pager --property=ExecStart --value {service}"
        )
        discovered = discover_config_path(service, meta.get("stdout") or "") if meta.get("success") else None
        path_source = "systemd_execstart" if discovered else "not_verified"
        if adapter is None or not adapter.config_check_command:
            return {
                "success": True, "supported": False, "target": target,
                "service": service, "valid": None,
                "config_file": discovered, "config_path_source": (
                    "systemd_execstart_unvalidated" if discovered else path_source
                ),
                "detail": "config_validation_adapter_unavailable",
            }
        if adapter.canonical_name == "haproxy" and not discovered:
            # HAProxy may use -f /opt/... or a config directory. Testing the
            # default path could give a false "valid" for a different config.
            return {
                "success": True, "supported": False, "target": target,
                "service": service, "valid": None, "config_file": None,
                "config_path_source": path_source,
                "detail": "running_config_path_unverified",
            }
        check_command = config_check_for_path(service, discovered)
        result = await self._run(target, check_command)
        diagnostic = (str(result.get("stderr") or "") + " " + str(result.get("stdout") or "")).lower()
        if not result.get("success") and any(
            marker in diagnostic
            for marker in ("permission denied", "access denied", "operation not permitted")
        ):
            # Only the fixed adapter command with a strictly validated path
            # may use the governed password-sudo fallback.
            result = await self._sudo(target, "sh -c " + shlex.quote(check_command))
        if result.get("exit_code") == 127:
            return {
                "success": True, "supported": False, "target": target,
                "service": service, "valid": None,
                "config_file": discovered, "config_path_source": path_source,
                "detail": "config_validation_binary_unavailable",
            }
        # A successful validator may print a *separate* sudo audit-log warning
        # when /var/log is full. That warning is not a failed nginx -t, and
        # must not be mixed into the validator diagnosis or used to veto Start.
        # If the command itself failed, preserve its entire stderr instead.
        stderr = str(result.get("stderr") or "")
        warnings = []
        if result.get("success") is True and result.get("exit_code") == 0:
            lines = stderr.splitlines()
            sudo_log_pattern = re.compile(
                r"^sudo:\s+unable to write log file:\s+"
                r"/var/log/sudo\.log:\s+No space left on device\s*$",
                re.IGNORECASE,
            )
            if any(sudo_log_pattern.fullmatch(line.strip()) for line in lines):
                warnings.append("sudo_audit_log_write_failed_enospc")
                stderr = "\n".join(line for line in lines
                                   if not sudo_log_pattern.fullmatch(line.strip()))
        detail = redact_text("\n".join(
            part for part in (
                str(result.get("stdout") or "").strip(),
                stderr.strip(),
            ) if part
        ))[:4000]
        parsed = parse_config_diagnostic(detail)
        config_file = parsed["config_file"] or discovered
        # A validator may point to an included file instead of the root config:
        # keep BOTH the systemd-selected file and the file with the error.
        common = {
            "target": target, "service": service,
            "adapter": adapter.canonical_name,
            "config_file": config_file,
            "root_config_file": discovered,
            "config_path_source": (
                "validator_output" if parsed["config_file"] else path_source
            ),
            "error_line": parsed["error_line"],
            "syntax_error": parsed["syntax_error"],
            "exit_code": result.get("exit_code"),
            "detail": detail,
            "nonfatal_warnings": warnings,
        }
        if not result.get("success") and any(
            marker in detail.lower() for marker in (
                "permission denied", "access denied", "operation not permitted",
                "sudo: a password is required",
            )
        ):
            return {
                **common, "success": False, "supported": True, "valid": None,
                "error": "config_validation_access_denied",
            }
        if not result.get("success") and result.get("exit_code") in {1, 2} and (
            parsed["syntax_error"]
            or any(marker in detail.lower() for marker in (
                "nginx:", "haproxy:", "syntax error", "configuration file", "httpd:",
            ))
        ):
            return {**common, "success": True, "supported": True, "valid": False}
        if not result.get("success"):
            return {
                **common, "success": False, "supported": True, "valid": None,
                "error": "config_validation_transport_failed",
            }
        return {**common, "success": True, "supported": True, "valid": True}

    async def start_service(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._sudo(target, f"systemctl start {service}")
        if not result.get("success"):
            logger.warning("vm_service_start_failed", target=target, service=service)
        return {"success": result.get("success", False), "service": service, "target": target, "error": None if result.get("success") else "service_start_failed"}

    async def restart_service(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._sudo(target, f"systemctl restart {service}")
        if not result.get("success"):
            logger.warning("vm_service_restart_failed", target=target, service=service)
        return {"success": result.get("success", False), "service": service, "target": target, "error": None if result.get("success") else "service_restart_failed"}

    async def reload_service(self, target: str, service: str) -> Dict[str, Any]:
        self._validate_service(service)
        result = await self._sudo(target, f"systemctl reload {service}")
        if not result.get("success"):
            logger.warning("vm_service_reload_failed", target=target, service=service)
        return {"success": result.get("success", False), "service": service, "target": target, "error": None if result.get("success") else "service_reload_failed"}