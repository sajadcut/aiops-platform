"""Agent transport loss must not be reported as proof that no config write ran."""
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


@pytest.mark.parametrize("transport_error", ["ssh_command_timeout", "local_command_timeout", "local_stdin_pipe_closed"])
@pytest.mark.asyncio
async def test_ambiguous_approved_apply_never_claims_no_write(monkeypatch, transport_error):
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "per-vm-test-token-with-adequate-length-abc123")
    values = {
        "config_file": FILE,
        "original_sha256": hashlib.sha256(SOURCE).hexdigest(),
        "candidate_sha256": hashlib.sha256(CANDIDATE).hexdigest(),
        "proposed_change": "remove_extra_opening_brace",
    }
    claims, signature = create_claim(
        approval_id=str(uuid4()), incident_id=str(uuid4()),
        target="vm-parity-01", service="nginx", **values,
    )

    class Connector:
        def _validate_target(self, value):
            assert value == claims["target"]
        def _validate_service(self, value):
            assert value == claims["service"]
        async def config_validate(self, target, service):
            return {
                "success": True, "supported": True, "valid": False,
                "config_file": FILE, "error_line": 1,
                "syntax_error": 'unexpected "{"',
            }
        async def _run(self, target, command, *, stdin_data=None):
            return {"success": True, "stdout": base64.b64encode(SOURCE).decode()}
        async def _sudo(self, target, command, *, stdin_data=None):
            return {"success": False, "error": transport_error, "stdout": "",
                    "stderr": "", "exit_code": None}

    outcome = await run_governed_change(
        Connector(), action="apply", target=claims["target"],
        service="nginx", execution_claims=claims,
        execution_signature=signature, **values,
    )
    assert outcome["success"] is False
    assert outcome["status"] == "config_apply_result_unknown"
    assert outcome["production_write_performed"] is None
    assert outcome["rollback_status"] == "unverified"
    assert outcome["service_recovery"]["attempted"] is False
