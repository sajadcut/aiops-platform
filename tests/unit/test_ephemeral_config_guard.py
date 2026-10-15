"""Regressions for helperless SSH/stdin config repair and its approval boundary."""
import base64
import hashlib
import subprocess

import pytest

from apps.config_change_authorization import create_claim
from integrations.vm.ephemeral_config_guard import build_ephemeral_guard
from integrations.vm.governed_config_change import run_governed_change

ORIGINAL = b"server localhost {{\n"
CANDIDATE = b"server localhost {\n"
SOURCE_HASH = hashlib.sha256(ORIGINAL).hexdigest()
TARGET_HASH = hashlib.sha256(CANDIDATE).hexdigest()


def test_ephemeral_script_has_valid_posix_syntax_and_only_trusted_static_code():
    command, script = build_ephemeral_guard(
        action="validate", profile="nginx", path="/etc/nginx/nginx.conf",
        original_sha256=SOURCE_HASH, candidate_sha256=TARGET_HASH,
        candidate=CANDIDATE.decode(),
    )
    result = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert command.startswith("/bin/sh -s -- validate nginx ")
    assert "aiops-config-guard" not in command
    assert CANDIDATE.decode() not in command
    assert CANDIDATE.decode() not in script
    assert base64.b64encode(CANDIDATE).decode() in script.replace("\n", "")
    assert "/usr/sbin/nginx -t" in script
    assert "unshare -m --propagation private" in script
    assert "mount --bind" in script
    assert "mount -o remount,bind,ro" in script
    assert "ROLLED_BACK" in script and "APPLIED_VERIFIED" in script
    assert "flock -x" in script and "sha256sum" in script
    assert "sudo su" not in script and "python" not in script.lower()


def test_ephemeral_config_payload_cannot_inject_shell_syntax():
    dangerous = "line\n__AIOPS_CONFIG_CANDIDATE_B64__\n$(touch /tmp/should_not_run)\n"
    cmd, body = build_ephemeral_guard(
        action="validate", profile="json_syntax", path="/opt/a/config.json",
        original_sha256=SOURCE_HASH, candidate_sha256=hashlib.sha256(dangerous.encode()).hexdigest(),
        candidate=dangerous,
    )
    assert dangerous not in cmd
    assert dangerous not in body
    assert "$(touch" not in body
    result = subprocess.run(["sh", "-n"], input=body, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("changes", [
    {"action": "restart"},
    {"profile": "arbitrary_shell"},
    {"path": "/etc/foo;touch /tmp/pwn.json"},
    {"path": "/etc/foo\nbar.json"},
    {"original_sha256": "A" * 64},
    {"candidate": ""},
])
def test_ephemeral_builder_rejects_untrusted_operation_or_metadata(changes):
    args = {
        "action": "validate", "profile": "json_syntax",
        "path": "/etc/example/config.json",
        "original_sha256": SOURCE_HASH,
        "candidate_sha256": TARGET_HASH,
        "candidate": CANDIDATE.decode(),
    }
    args.update(changes)
    with pytest.raises(ValueError):
        build_ephemeral_guard(**args)


@pytest.mark.asyncio
async def test_direct_apply_without_valid_signed_claim_is_denied_before_ssh():
    class NoSSH:
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)

        def __getattr__(self, attr):
            raise AssertionError(f"SSH should not be attempted: {attr}")

    with pytest.raises(PermissionError, match="config_execution_claim"):
        await run_governed_change(
            NoSSH(), action="apply", target="192.0.2.16", service="nginx",
            config_file="/etc/nginx/nginx.conf",
            original_sha256=SOURCE_HASH,
            candidate_sha256=TARGET_HASH,
            proposed_change="remove_extra_opening_brace",
            execution_claims={"approval_id": "forged"},
            execution_signature="0" * 64,
        )


@pytest.mark.asyncio
async def test_approved_apply_still_requires_identical_signed_file_hashes(monkeypatch):
    monkeypatch.setenv("AIOPS_CONFIG_APPLY_SIGNING_SECRET", "a-real-unique-secret-for-tests-1234567890")
    claims, signature = create_claim(
        approval_id="1b61f2a2-f9dd-4281-856f-d77ac85872be",
        incident_id="848420a5-3cad-48de-a1e1-e730f8ed8767",
        target="192.0.2.16", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256=SOURCE_HASH,
        candidate_sha256=TARGET_HASH,
        proposed_change="remove_extra_opening_brace",
    )
    class NoSSH:
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)

        def __getattr__(self, attr):
            raise AssertionError(f"SSH should not be attempted: {attr}")

    with pytest.raises(PermissionError, match="config_execution_claim_binding_changed"):
        await run_governed_change(
            NoSSH(), action="apply", target="192.0.2.16", service="nginx",
            config_file="/etc/nginx/nginx.conf",
            original_sha256=SOURCE_HASH,
            candidate_sha256="c" * 64,
            proposed_change="remove_extra_opening_brace",
            execution_claims=claims,
            execution_signature=signature,
        )


@pytest.mark.asyncio
async def test_signed_approved_apply_uses_fixed_root_script_and_reports_verification(monkeypatch):
    monkeypatch.setenv("AIOPS_CONFIG_APPLY_SIGNING_SECRET", "a-real-unique-secret-for-tests-1234567890")
    claims, signature = create_claim(
        approval_id="1b61f2a2-f9dd-4281-856f-d77ac85872be",
        incident_id="848420a5-3cad-48de-a1e1-e730f8ed8767",
        target="192.0.2.16", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256=SOURCE_HASH,
        candidate_sha256=TARGET_HASH,
        proposed_change="remove_extra_opening_brace",
    )
    commands = []

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
            commands.append(("read", command, stdin_data))
            return {"success": True, "stdout": base64.b64encode(ORIGINAL).decode()}

        async def _sudo(self, target, command, *, stdin_data=None):
            commands.append(("sudo", command, stdin_data))
            return {"success": True, "exit_code": 0, "stdout": "APPLIED_VERIFIED"}

    result = await run_governed_change(
        Edge(), action="apply", target="192.0.2.16", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256=SOURCE_HASH,
        candidate_sha256=TARGET_HASH,
        proposed_change="remove_extra_opening_brace",
        execution_claims=claims,
        execution_signature=signature,
    )
    assert result["success"] is True
    assert result["status"] == "applied_verified"
    assert result["production_write_performed"] is True
    assert len(commands) == 2
    assert commands[1][1].startswith("/bin/sh -s -- apply nginx ")
    assert "APPLIED_VERIFIED" in commands[1][2]
    assert ORIGINAL.decode() not in commands[1][1]
    assert CANDIDATE.decode() not in commands[1][2]
