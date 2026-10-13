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


@pytest.mark.asyncio
async def test_config_validate_retries_sudo_with_ssh_password_when_permission_denied(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "password")
    monkeypatch.setattr(settings, "SSH_USERNAME", "svc-aiops")
    monkeypatch.setattr(settings, "SSH_PASSWORD", "test-password")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx", "haproxy"])
    connector = SSHVMConnector()
    commands = []

    async def fake_run(target, command, *, stdin_data=None):
        commands.append((target, command, stdin_data))
        if command.startswith("sudo -S "):
            return {"success": True, "exit_code": 0, "stdout": "configuration ok", "stderr": ""}
        if command.startswith("sudo -n "):
            return {"success": False, "exit_code": 1, "stderr": "sudo: a password is required"}
        return {"success": False, "exit_code": 1, "stderr": "permission denied reading certificate"}

    monkeypatch.setattr(connector, "_run", fake_run)
    for service in ("nginx", "haproxy"):
        result = await connector.config_validate("10.100.6.199", service)
        assert result["success"] is True
        assert result["valid"] is True
    assert len(commands) == 6
    assert all("test-password" not in command for _, command, _ in commands)
    assert all(stdin is None for _, _, stdin in commands if stdin != "test-password\n")
    assert len([stdin for _, _, stdin in commands if stdin == "test-password\n"]) == 2


@pytest.mark.asyncio
async def test_config_validate_reports_real_syntax_failure_as_invalid(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    connector = SSHVMConnector()

    async def fake_run(target, command):
        return {
            "success": False, "exit_code": 1, "stdout": "",
            "stderr": "nginx: [emerg] invalid directive; configuration file test failed",
        }

    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.config_validate("10.100.6.199", "nginx")
    assert result["success"] is True
    assert result["supported"] is True
    assert result["valid"] is False
    assert result["exit_code"] == 1
