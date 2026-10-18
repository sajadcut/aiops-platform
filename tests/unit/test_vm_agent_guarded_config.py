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
