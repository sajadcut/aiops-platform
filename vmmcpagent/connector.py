"""On-host VM MCP transport owned by the self-contained vmmcpagent package.

This implementation reuses the legacy SSH VM tool business logic without
establishing an SSH connection. Do not add a generic shell RPC.

Only named MCP operations may reach this connector. There is deliberately no
remote shell tool or RPC method accepting an arbitrary command.
"""
from __future__ import annotations

import asyncio
import os
import re
import signal
import time
from typing import Any, Dict, Optional

from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.vm.ssh_connector import SSHVMConnector, _SAFE_HOST, _SAFE_SERVICE


class LocalVMConnector(SSHVMConnector):
    """Run existing bounded VM diagnostics/repairs on this host, not over SSH."""

    source_name = "vm_agent"
    # Root-owned fixed guard with on-host public signature verification;
    # never sudo an arbitrary stdin-controlled POSIX shell on the agent.
    uses_root_owned_config_guard = True
    # Only process memory; never persist API-delivered sudo credentials.
    _session_sudo_password: Optional[str] = None

    @classmethod
    def execution_identity(cls) -> str:
        if os.name != "posix":
            raise RuntimeError("vm_agent_requires_linux_posix")
        import pwd  # Linux only; preserve Windows Control Plane imports.
        return pwd.getpwuid(os.geteuid()).pw_name

    @classmethod
    def set_session_credentials(cls, username: str, password: str) -> None:
        expected = str(settings.VM_AGENT_EXEC_USERNAME or "").strip()
        if not expected or username != expected or cls.execution_identity() != expected:
            raise PermissionError("vm_agent_exec_username_mismatch")
        if (not isinstance(password, str) or not password
                or any(char in password for char in ("\n", "\r", "\x00"))):
            raise PermissionError("vm_agent_sudo_password_invalid")
        cls._session_sudo_password = password

    @classmethod
    def clear_session_credentials(cls) -> None:
        cls._session_sudo_password = None

    async def _sudo(self, target: str, fixed_command: str, *,
                    stdin_data: Optional[str] = None) -> Dict[str, Any]:
        self._validate_target(target)
        # Reuse only trusted allowlisted sudo operations from SSHVMConnector.
        password = type(self)._session_sudo_password
        if password:
            # Exactly one invocation, with a fresh sudo authentication.
            # Never probe the same mutable action and then try it again.
            payload = password + "\n" + (stdin_data if stdin_data is not None else "")
            result = await self._run(
                target, "sudo -k -S -p '' " + fixed_command, stdin_data=payload)
            for field in ("stdout", "stderr"):
                if field in result:
                    result[field] = str(result[field]).replace(password, "[REDACTED]")
            return result
        # Legacy inbound/local NOPASSWD mode remains available without a
        # transmitted credential; never attempt an interactive password prompt.
        result = await self._run(
            target, "sudo -n " + fixed_command, stdin_data=stdin_data)
        if self._sudo_requires_password(result):
            return {"success": False, "error": "vm_agent_sudo_credentials_not_provisioned"}
        return result

    @classmethod
    def _validate_runtime_security(cls) -> None:
        target = str(settings.VM_AGENT_TARGET or "").strip()
        allowed = settings.VM_AGENT_ALLOWED_SERVICES
        if not target or not _SAFE_HOST.fullmatch(target):
            raise RuntimeError("vm_agent_target_required")
        if not allowed or any(not _SAFE_SERVICE.fullmatch(str(x)) for x in allowed):
            raise RuntimeError("vm_agent_allowed_services_required")
        if settings.SSH_ENABLED:
            raise RuntimeError("vm_agent_must_not_enable_ssh")
        if settings.VM_AGENT_CONNECTION_MODE == "outbound" and settings.APP_ENV == "production":
            expected = str(settings.VM_AGENT_EXEC_USERNAME or "").strip()
            if not expected or cls.execution_identity() != expected:
                raise RuntimeError("vm_agent_runtime_exec_user_mismatch")
        if os.name != "posix":
            raise RuntimeError("vm_agent_requires_linux_posix")
        # A dedicated unprivileged systemd service account is essential; sudo
        # is restricted separately by the host's administrator.
        if settings.APP_ENV == "production" and hasattr(os, "geteuid") and os.geteuid() == 0:
            raise RuntimeError("vm_agent_must_not_run_as_root")

    @staticmethod
    def _auth_mode() -> str:
        # Do not load or use an SSH password for local sudo fallback.
        return "key"

    def _validate_target(self, target: str) -> None:
        if not target or not _SAFE_HOST.fullmatch(target):
            raise ValueError("invalid_vm_target")
        if target != settings.VM_AGENT_TARGET.strip():
            raise PermissionError("vm_target_not_allowed")

    def _validate_service(self, service: str) -> None:
        if not service or not _SAFE_SERVICE.fullmatch(service):
            raise ValueError("invalid_service_name")
        if service not in settings.VM_AGENT_ALLOWED_SERVICES:
            raise PermissionError("vm_service_not_allowed")

    async def _run(self, target: str, command: str, *,
                   stdin_data: Optional[str] = None) -> Dict[str, Any]:
        self._validate_target(target)
        # Commands originate exclusively from SSHVMConnector's fixed,
        # allowlisted diagnostic and guarded-remediation methods. Never expose
        # this method as a network tool or pass user-authored shell text to it.
        started = time.perf_counter()
        # Do not log command text: config-repair stdin and discovered service
        # configuration may contain credentials or personal information.
        logger.info("vm_agent_local_request", target=target,
                    command_class=("privileged" if command.startswith("sudo ")
                                   else "diagnostic"), stdin_supplied=stdin_data is not None)
        process = await asyncio.create_subprocess_exec(
            "/bin/sh", "-c", command,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            # The on-host worker holds API bearer, Ed25519 signing seed and
            # possibly an LLM key. Diagnostic child processes (including
            # privileged sudo commands) must never inherit those secrets.
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C", "LC_ALL": "C"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin_data.encode("utf-8") if stdin_data is not None else None),
                timeout=self._command_deadline_seconds(command),
            )
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
            logger.warning("vm_agent_local_response", target=target,
                           success=False, error_type="local_command_timeout",
                           response_time_ms=round((time.perf_counter() - started)*1000, 3))
            return {"success": False, "error": "local_command_timeout",
                    "execution_time": time.perf_counter() - started}
        except asyncio.CancelledError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
            raise
        elapsed = time.perf_counter() - started
        # Never put command text, stdin, stdout or stderr in application logs.
        logger.info("vm_agent_operation_completed", target=target,
                    success=process.returncode == 0, exit_code=process.returncode,
                    response_time_ms=round(elapsed * 1000, 3),
                    stdout_bytes=len(stdout), stderr_bytes=len(stderr))
        # Bound response size; the existing config reviewers decode only their
        # expected subset of command output and fail closed on truncation.
        max_output = 8 * 1024 * 1024
        if len(stdout) > max_output or len(stderr) > max_output:
            return {"success": False, "error": "local_output_limit_exceeded",
                    "execution_time": elapsed}
        return {"success": process.returncode == 0,
                "exit_code": process.returncode,
                "stdout": stdout.decode(errors="replace").strip(),
                "stderr": stderr.decode(errors="replace").strip(),
                "execution_time": elapsed}
