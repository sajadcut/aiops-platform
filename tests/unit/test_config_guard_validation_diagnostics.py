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
