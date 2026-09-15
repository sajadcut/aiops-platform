import asyncio

import pytest

import integrations.vm.ssh_connector as ssh_module
from domain.contracts.config import settings
from integrations.vm.ssh_connector import SSHVMConnector


class _FakeSSHResult:
    exit_status = 0
    stdout = "connected"
    stderr = ""


class _FakeSSHConnection:
    async def run(self, command, check=False):
        assert command == "printf connected"
        assert check is False
        return _FakeSSHResult()


class _FakeSSHContext:
    async def __aenter__(self):
        return _FakeSSHConnection()

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _configure_password_mode(monkeypatch, *, app_env="test"):
    monkeypatch.setattr(settings, "APP_ENV", app_env)
    monkeypatch.setattr(settings, "SSH_ENABLED", True)
    monkeypatch.setattr(settings, "SSH_USERNAME", "svc-aiops")
    monkeypatch.setattr(settings, "SSH_PRIVATE_KEY_PATH", None)
    monkeypatch.setattr(settings, "SSH_KNOWN_HOSTS", None if app_env != "production" else "/etc/ssh/ssh_known_hosts")
    monkeypatch.setattr(settings, "SSH_STRICT_HOST_KEY_CHECKING", app_env == "production")
    monkeypatch.setattr(settings, "SSH_PORT", 22)
    monkeypatch.setattr(settings, "SSH_CONNECT_TIMEOUT", 5)
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm01"])
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["haproxy"])
    monkeypatch.setenv("SSH_AUTH_MODE", "password")
    monkeypatch.setenv("SSH_PASSWORD", "test-only-password")


def test_password_auth_mode_does_not_require_private_key_in_production(monkeypatch):
    _configure_password_mode(monkeypatch, app_env="production")
    connector = SSHVMConnector()
    assert connector._auth_mode() == "password"


def test_password_auth_mode_requires_password(monkeypatch):
    _configure_password_mode(monkeypatch)
    monkeypatch.delenv("SSH_PASSWORD")
    with pytest.raises(RuntimeError, match="SSH_PASSWORD is required"):
        SSHVMConnector()


def test_invalid_auth_mode_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setenv("SSH_AUTH_MODE", "keyboard-interactive")
    with pytest.raises(RuntimeError, match="SSH_AUTH_MODE must be key or password"):
        SSHVMConnector()


@pytest.mark.asyncio
async def test_password_auth_uses_asyncssh_and_not_subprocess(monkeypatch):
    _configure_password_mode(monkeypatch)
    captured = {}

    def fake_connect(host, **kwargs):
        captured["host"] = host
        captured.update(kwargs)
        return _FakeSSHContext()

    async def subprocess_must_not_run(*args, **kwargs):
        raise AssertionError("password authentication must not place secrets in a subprocess command line")

    monkeypatch.setattr(ssh_module.asyncssh, "connect", fake_connect)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", subprocess_must_not_run)

    connector = SSHVMConnector()
    assert await connector.health_check("vm01") is True
    assert captured["host"] == "vm01"
    assert captured["username"] == "svc-aiops"
    assert captured["password"] == "test-only-password"
    assert captured["client_keys"] == []
    assert captured["known_hosts"] is None
