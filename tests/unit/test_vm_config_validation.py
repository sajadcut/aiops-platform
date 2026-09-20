import pytest

from domain.contracts.config import settings
from integrations.vm.ssh_connector import SSHVMConnector


@pytest.mark.asyncio
async def test_config_validate_propagates_ssh_failure(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    connector = SSHVMConnector()

    async def failed_run(target, command):
        return {
            "success": False,
            "exit_code": 255,
            "stdout": "",
            "stderr": "Permission denied (publickey,password).",
        }

    monkeypatch.setattr(connector, "_run", failed_run)
    result = await connector.config_validate("10.100.6.199", "nginx")

    assert result["success"] is False
    assert result["valid"] is None
    assert result["exit_code"] == 255
    assert result["error"] == "config_validation_transport_failed"
    assert "Permission denied" in result["detail"]
