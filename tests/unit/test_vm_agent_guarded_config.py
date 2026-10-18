"""Exercise the privileged config path selected only by installed on-host agents."""
from __future__ import annotations

import base64
import hashlib
from uuid import uuid4

import pytest

from apps.config_change_authorization import create_claim
from domain.contracts.config import settings
from integrations.vm.governed_config_change import run_governed_change

SOURCE = b"server 127.0.0.1 {{\n"
CANDIDATE = b"server 127.0.0.1 {\n"
FILE = "/etc/nginx/nginx.conf"
VALUES = {
    "config_file": FILE,
    "original_sha256": hashlib.sha256(SOURCE).hexdigest(),
    "candidate_sha256": hashlib.sha256(CANDIDATE).hexdigest(),
    "proposed_change": "remove_extra_opening_brace",
}


@pytest.mark.parametrize("action", ["validate", "apply"])
@pytest.mark.asyncio
async def test_installed_agent_uses_signed_fixed_guard_and_not_root_shell(
        monkeypatch, action):
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN",
                        "agent-01-only-unique-secret-123456789abcdef")
    monkeypatch.setenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY",
                       base64.b64encode(bytes([27]) * 32).decode())
    calls = []
    claims, signature = create_claim(
        approval_id=str(uuid4()), incident_id=str(uuid4()),
        target="vm-local-01", service="nginx", **VALUES,
    )

    class Connector:
        uses_root_owned_config_guard = True

        def _validate_target(self, target):
            assert target == "vm-local-01"

        def _validate_service(self, service):
            assert service == "nginx"

        async def config_validate(self, target, service):
            return {
                "success": True, "supported": True, "valid": False,
                "config_file": FILE, "error_line": 1,
                "syntax_error": 'unexpected "{"',
            }

        async def _run(self, target, command, *, stdin_data=None):
            return {"success": True, "stdout": base64.b64encode(SOURCE).decode()}

        async def _sudo(self, target, command, *, stdin_data=None):
            calls.append((command, stdin_data))
            return {"success": True,
                    "stdout": "APPLIED_VERIFIED" if action == "apply" else "VALIDATED"}

    outcome = await run_governed_change(
        Connector(), action=action, target=claims["target"], service="nginx",
        execution_claims=claims if action == "apply" else None,
        execution_signature=signature if action == "apply" else None,
        **VALUES,
    )
    assert outcome["success"] is True, outcome
    assert len(calls) == 1
    command, stdin_data = calls[0]
    assert command.startswith(f"/usr/local/sbin/aiops-config-guard {action} nginx ")
    assert "/bin/sh -s" not in command
    assert "sudo" not in command
    assert stdin_data == CANDIDATE.decode()
    assert SOURCE.decode() not in command
    assert CANDIDATE.decode() not in command
    if action == "apply":
        assert outcome["status"] == "applied_verified"
        assert outcome["production_write_performed"] is True
        assert len(command.split()) == 11  # fixed guard + 10 validated arguments
    else:
        assert outcome["status"] == "isolated_vendor_validation_passed"
        assert outcome["production_write_performed"] is False
        assert len(command.split()) == 6  # guard + 5 validated arguments


def test_root_guard_signer_preflight_detects_missing_mismatch_and_valid_key(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import apps.config_change_authorization as auth

    seed = bytes([19]) * 32
    public_file = tmp_path / "verify.pem"
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    public_file.write_bytes(public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(auth, "_ROOT_GUARD_VERIFY_PEM", str(public_file))
    monkeypatch.delenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY", raising=False)
    assert auth.root_guard_apply_signing_status() == (False, "config_guard_private_key_missing")
    monkeypatch.setenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY", base64.b64encode(seed).decode())
    assert auth.root_guard_apply_signing_status() == (True, "ready")
    monkeypatch.setenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY",
                       base64.b64encode(bytes([20]) * 32).decode())
    assert auth.root_guard_apply_signing_status() == (False, "config_guard_keypair_mismatch")
    monkeypatch.setenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY", base64.b64encode(seed).decode())
    public_file.unlink()
    assert auth.root_guard_apply_signing_status() == (False, "config_guard_verify_key_missing")
    public_file.symlink_to(tmp_path / "not-a-verifier")
    assert auth.root_guard_apply_signing_status() == (False, "config_guard_verify_key_invalid")


@pytest.mark.asyncio
async def test_missing_signing_key_never_runs_privileged_apply(monkeypatch):
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN",
                        "agent-01-only-unique-secret-123456789abcdef")
    claims, signed = create_claim(
        approval_id=str(uuid4()), incident_id=str(uuid4()),
        target="vm-local-01", service="nginx", **VALUES,
    )
    monkeypatch.delenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY", raising=False)
    class Connector:
        uses_root_owned_config_guard = True
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)
        async def config_validate(self, target, service):
            return {"success": True, "supported": True, "valid": False,
                    "config_file": FILE, "error_line": 1,
                    "syntax_error": 'unexpected "{"'}
        async def _run(self, target, command, *, stdin_data=None):
            return {"success": True, "stdout": base64.b64encode(SOURCE).decode()}
        async def _sudo(self, target, command, *, stdin_data=None):
            raise AssertionError("No privileged executor must run")
    result = await run_governed_change(
        Connector(), action="apply", target="vm-local-01", service="nginx",
        execution_claims=claims, execution_signature=signed, **VALUES,
    )
    assert result["status"] == "config_guard_request_rejected"
    assert result["failure_reason"] == "config_guard_private_key_missing"
    assert result["production_write_performed"] is False


@pytest.mark.asyncio
async def test_api_blocks_unready_agent_signer_before_consuming_approval(monkeypatch):
    """A valid isolated nginx -t is not enough to spend a one-use Approval."""
    from types import SimpleNamespace
    from fastapi import HTTPException
    from apps.api import config_change_execution as module

    approval = {"status": "approved", "incident_id": str(uuid4())}
    meta = {**VALUES, "target": "vm-local-01",
            "isolated_validation": True,
            "validation_scope":
                "nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies"}
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class ApprovalStore:
        def __init__(self, db): pass
        async def get(self, approval_id): return approval
        async def consume(self, *args, **kwargs):
            raise AssertionError("Must NOT consume Approval before signer is ready")
    validator_called = []
    class Agent:
        async def config_change_validate(self, target, **kwargs):
            validator_called.append((target, kwargs))
            assert target == meta["target"]
            assert kwargs["original_sha256"] == meta["original_sha256"]
            return {
                "success": True, "status": "isolated_vendor_validation_passed",
                "isolated_validation": True, "production_write_performed": False,
                "original_sha256": meta["original_sha256"],
                "candidate_sha256": meta["candidate_sha256"],
                "validation_scope":
                    "nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies",
                "apply_signing_ready": False,
                "apply_signing_status": "config_guard_private_key_missing",
            }
    async def matching(db, record, metadata):
        return True
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent_pull")
    monkeypatch.setattr(module, "AsyncSessionLocal", Session)
    monkeypatch.setattr(module, "PostgreSQLApprovalStore", ApprovalStore)
    monkeypatch.setattr(module, "_fields", lambda record: meta)
    monkeypatch.setattr(module, "_same_incident_candidate", matching)
    monkeypatch.setattr(module, "VMEdgeMCPClient", Agent)
    with pytest.raises(HTTPException) as exc:
        await module.execute_config(
            uuid4(), identity=SimpleNamespace(subject="sre"),
        )
    assert exc.value.status_code == 503, (exc.value.detail, validator_called)
    assert exc.value.detail == "config_guard_private_key_missing"
