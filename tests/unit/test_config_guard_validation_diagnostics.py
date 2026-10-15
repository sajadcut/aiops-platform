"""Regression: deployed guard returning rc=1 must not be blamed on nginx -t."""
import base64
import hashlib
from pathlib import Path

import pytest

from apps.api.config_change_review import _review_progress
from integrations.vm.governed_config_change import (
    classify_config_guard_failure, run_governed_change,
)

SOURCE = b"server localhost {{\n"
CANDIDATE = b"server localhost {\n"
SOURCE_SHA = hashlib.sha256(SOURCE).hexdigest()
CANDIDATE_SHA = hashlib.sha256(CANDIDATE).hexdigest()

@pytest.mark.parametrize("stderr,code,expected", [
    ("sudo: a password is required", 1, "config_guard_sudo_nopasswd_required"),
    ("sudo: user is not allowed to execute this command", 1, "config_guard_sudo_policy_denied"),
    ("sudo: /usr/local/sbin/aiops-config-guard: command not found", 1, "config_guard_helper_missing"),
    ("sudo: Permission denied", 1, "config_guard_helper_permission_denied"),
    ("untrusted secret contents", 1, "config_guard_sudo_or_invocation_failed"),
    ("", 42, "config_guard_prerequisite_failed"),
    ("", 45, "config_guard_source_hash_changed"),
    ("", 47, "config_guard_vendor_syntax_failed"),
    ("", 50, "config_guard_mount_namespace_unavailable"),
    ("", 51, "config_guard_isolated_mount_failed"),
])
def test_guard_diagnostic_classified_without_exposing_stderr(stderr, code, expected):
    result = {"success": False, "exit_code": code, "stderr": stderr}
    assert classify_config_guard_failure(result) == expected
    if stderr:
        assert stderr not in classify_config_guard_failure(result)


@pytest.mark.asyncio
async def test_live_rc1_is_nonapprovable_and_safe_for_api():
    class Edge:
        _validate_target = staticmethod(lambda x: None)
        _validate_service = staticmethod(lambda x: None)
        async def config_validate(self, target, service):
            return {
                "success": True, "supported": True, "valid": False,
                "config_file": "/etc/nginx/nginx.conf", "error_line": 1,
                "syntax_error": 'unexpected "{"',
            }
        async def _sudo(self, target, command, *, stdin_data=None):
            return await self._run(target, "sudo -n " + command, stdin_data=stdin_data)

        async def _run(self, target, command, *, stdin_data=None):
            if "aiops-config-guard" in command:
                assert stdin_data == CANDIDATE.decode()
                return {"success": False, "exit_code": 1,
                        "stderr": "sudo: a password is required",
                        "stdout": ""}
            return {"success": True, "stdout": base64.b64encode(SOURCE).decode()}

    result = await run_governed_change(
        Edge(), action="validate", target="192.0.2.11", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256=SOURCE_SHA, candidate_sha256=CANDIDATE_SHA,
        proposed_change="remove_extra_opening_brace",
    )
    assert result["success"] is False
    assert result["status"] == "config_guard_sudo_nopasswd_required"
    assert result["guard_exit_code"] == 1
    assert result["isolated_validation"] is False
    assert result["production_write_performed"] is False
    assert "sudo:" not in repr(result)


def test_blocked_reason_is_visible_after_reload_but_cannot_make_ticket_actionable():
    from apps.approval_service.postgres import PostgreSQLApprovalStore
    from inspect import getsource
    record = {
        "approval_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "status": "pending_validation",
        "metadata": {
            "isolated_validation": False,
            "workflow": "config_change",
            "validation_last_reason": "config_guard_sudo_nopasswd_required",
            "validation_last_exit_code": 1,
        }
    }
    info = _review_progress(
        status="pending_validation", decision="request_change_approval",
        proposal={"service": "nginx"}, approval=record,
    )
    assert info["validation_pipeline_status"] == "blocked"
    assert info["validation_reason"] == "config_guard_sudo_nopasswd_required"
    assert info["guard_exit_code"] == 1
    assert info["approval_actionable"] is False
    assert info["execution_authority"] is False
    impl = getsource(PostgreSQLApprovalStore.record_config_validation_failure)
    assert "status='pending_validation'" in impl
    assert "SET metadata=" in impl
    assert "SET status=" not in impl


def test_guard_distinguishes_isolation_problem_and_vendor_error():
    script = (Path(__file__).resolve().parents[2] / "scripts/vm/aiops-config-guard").read_text()
    assert "unshare -m --propagation private -- /bin/true" in script
    assert "exit 50" in script
    assert "exit 51" in script
    assert "exit 47" in script


@pytest.mark.asyncio
async def test_guard_uses_existing_ssh_user_password_for_sudo_with_candidate():
    """sudo -n failure must transparently retry with the SAME SSH password.

    Both password and hash-bound candidate are sent through SSH stdin, never
    command arguments; the helper receives only candidate bytes after sudo
    consumes its password line.
    """
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = object.__new__(SSHVMConnector)
    password = "same-ssh-user-password-123!"
    candidate = '{"apiKey":"NEVER_LOG_ME","valid":true}\n'
    calls = []

    async def fake_run(target, command, *, stdin_data=None):
        calls.append((target, command, stdin_data))
        if command.startswith("sudo -n "):
            return {"success": False, "exit_code": 1,
                    "stderr": "sudo: a password is required"}
        assert command.startswith("sudo -k -S -p '' /usr/local/sbin/aiops-config-guard ")
        assert stdin_data == password + "\n" + candidate
        return {"success": True, "exit_code": 0, "stdout": "VALIDATED"}

    connector._run = fake_run
    connector._auth_mode = lambda: "password"
    connector._password = lambda: password
    response = await connector._sudo(
        "192.0.2.16",
        "/usr/local/sbin/aiops-config-guard validate custom-json /etc/example/config.json "
        + "a" * 64 + " " + "b" * 64,
        stdin_data=candidate,
    )
    assert response["success"] is True
    assert len(calls) == 2
    assert calls[0][2] == candidate
    assert calls[1][2] == password + "\n" + candidate
    assert all(password not in cmd and candidate not in cmd for _, cmd, _ in calls)


@pytest.mark.asyncio
async def test_guard_preserves_candidate_when_sudo_nopasswd_already_works():
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = object.__new__(SSHVMConnector)
    calls = []

    async def fake_run(target, command, *, stdin_data=None):
        calls.append((command, stdin_data))
        return {"success": True, "exit_code": 0, "stdout": "VALIDATED"}

    connector._run = fake_run
    connector._auth_mode = lambda: "password"
    connector._password = lambda: "ssh-secret-not-needed"
    result = await connector._sudo(
        "192.0.2.16", "/usr/local/sbin/aiops-config-guard validate",
        stdin_data="sensitive-config\n",
    )
    assert result["success"] is True
    assert calls == [("sudo -n /usr/local/sbin/aiops-config-guard validate",
                      "sensitive-config\n")]


@pytest.mark.asyncio
async def test_denied_sudo_policy_never_falls_back_to_su_or_password():
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = object.__new__(SSHVMConnector)
    calls = []

    async def fake_run(target, command, *, stdin_data=None):
        calls.append((command, stdin_data))
        return {"success": False, "exit_code": 1,
                "stderr": "sudo: user is not allowed to execute this command"}

    connector._run = fake_run
    connector._auth_mode = lambda: "password"
    connector._password = lambda: "never-send-this-password"
    result = await connector._sudo(
        "192.0.2.16", "/usr/local/sbin/aiops-config-guard validate",
        stdin_data="candidate\n",
    )
    assert result["success"] is False
    assert len(calls) == 1
    assert calls[0][0].startswith("sudo -n ")


@pytest.mark.parametrize("probe,code", [
    ("MISSING", "config_guard_helper_missing"),
    ("SYMLINK", "config_guard_helper_symlink_refused"),
    ("NOT_REGULAR", "config_guard_helper_not_regular"),
    ("PRESENT 1000 1000 750", "config_guard_helper_unsafe_metadata"),
    ("PRESENT 0 0 755", "config_guard_helper_unsafe_metadata"),
    ("", "config_guard_preflight_unavailable"),
])
@pytest.mark.asyncio
async def test_config_guard_preflight_reports_precise_provisioning_blocker(probe, code):
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = object.__new__(SSHVMConnector)
    connector._validate_target = lambda target: None
    commands = []

    async def inspect(target, command, *, stdin_data=None):
        commands.append((command, stdin_data))
        return {"success": True, "stdout": probe}

    connector._run = inspect
    outcome = await connector.config_guard_preflight("192.0.2.16")
    assert outcome == {"success": False, "status": code}
    assert len(commands) == 1
    assert "sudo" not in commands[0][0]
    assert commands[0][1] is None


@pytest.mark.asyncio
async def test_config_guard_preflight_accepts_only_root_owned_mode_0750():
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = object.__new__(SSHVMConnector)
    connector._validate_target = lambda target: None

    async def inspect(target, command, *, stdin_data=None):
        return {"success": True, "stdout": "PRESENT 0 0 750"}

    connector._run = inspect
    outcome = await connector.config_guard_preflight("192.0.2.16")
    assert outcome == {"success": True, "status": "config_guard_helper_present"}


@pytest.mark.asyncio
async def test_missing_helper_preflight_cannot_start_sudo_or_write_production():
    class Edge:
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)

        async def config_validate(self, target, service):
            return {
                "success": True, "supported": True, "valid": False,
                "config_file": "/etc/nginx/nginx.conf", "error_line": 1,
                "syntax_error": 'unexpected "{"',
            }

        async def _run(self, target, command, *, stdin_data=None):
            assert "sudo" not in command
            return {"success": True, "stdout": base64.b64encode(SOURCE).decode()}

        async def config_guard_preflight(self, target):
            return {"success": False, "status": "config_guard_helper_missing"}

        async def _sudo(self, *args, **kwargs):
            raise AssertionError("no privileged command before guard provisioning")

    result = await run_governed_change(
        Edge(), action="validate", target="192.0.2.11", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256=SOURCE_SHA, candidate_sha256=CANDIDATE_SHA,
        proposed_change="remove_extra_opening_brace",
    )
    assert result["status"] == "config_guard_helper_missing"
    assert result["isolated_validation"] is False
    assert result["production_write_performed"] is False


def test_non_helper_missing_dependency_is_not_misclassified():
    assert classify_config_guard_failure({
        "exit_code": 1, "stderr": "jq: command not found",
    }) == "config_guard_execution_failed"


def test_windows_vm_guard_installer_requires_explicit_operator_sudo():
    script = (Path(__file__).resolve().parents[2]
              / "scripts/vm/Install-AIOpsConfigGuard.ps1").read_text()
    assert "Get-FileHash -Algorithm SHA256" in script
    assert '.Replace("`r`n", "`n")' in script
    assert "UTF8Encoding" in script
    assert "StrictHostKeyChecking=yes" in script
    assert "sudo install -o root -g root -m 0750" in script
    assert "sudo sha256sum" in script
    assert "sudo su" not in script.replace("unrestricted `sudo su`", "")
    assert "config_change_apply" not in script


@pytest.mark.asyncio
async def test_provisioned_helper_validation_can_advance_without_production_write():
    calls = []
    class Edge:
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)

        async def config_validate(self, target, service):
            return {
                "success": True, "supported": True, "valid": False,
                "config_file": "/etc/nginx/nginx.conf", "error_line": 1,
                "syntax_error": 'unexpected "{"',
            }

        async def _run(self, target, command, *, stdin_data=None):
            calls.append(("read", command, stdin_data))
            return {"success": True, "stdout": base64.b64encode(SOURCE).decode()}

        async def config_guard_preflight(self, target):
            calls.append(("preflight", target, None))
            return {"success": True, "status": "config_guard_helper_present"}

        async def _sudo(self, target, command, *, stdin_data=None):
            calls.append(("sudo", command, stdin_data))
            return {"success": True, "exit_code": 0, "stdout": "VALIDATED"}

    result = await run_governed_change(
        Edge(), action="validate", target="192.0.2.11", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256=SOURCE_SHA, candidate_sha256=CANDIDATE_SHA,
        proposed_change="remove_extra_opening_brace",
    )
    assert result["status"] == "isolated_vendor_validation_passed"
    assert result["isolated_validation"] is True
    assert result["production_write_performed"] is False
    assert [row[0] for row in calls] == ["read", "preflight", "sudo"]
    assert calls[-1][2] == CANDIDATE.decode()
    assert calls[-1][1].startswith("/usr/local/sbin/aiops-config-guard validate nginx ")


def test_vm_provision_script_refuses_existing_helper_symlink():
    script = (Path(__file__).resolve().parents[2]
              / "scripts/vm/Install-AIOpsConfigGuard.ps1").read_text()
    assert "sudo test ! -L $targetFile" in script
