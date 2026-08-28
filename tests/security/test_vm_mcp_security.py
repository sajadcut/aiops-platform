import pytest

from domain.contracts.config import settings
from integrations.vm.ssh_connector import SSHVMConnector


def test_vm_target_and_service_allowlists(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm01"])
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    connector = SSHVMConnector()
    connector._validate_target("vm01")
    connector._validate_service("nginx")
    with pytest.raises(PermissionError):
        connector._validate_target("vm02")
    with pytest.raises(PermissionError):
        connector._validate_service("postgresql")


def test_production_vm_edge_rejects_root_and_missing_host_pinning(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "SSH_ENABLED", True)
    monkeypatch.setattr(settings, "SSH_USERNAME", "root")
    monkeypatch.setattr(settings, "SSH_PRIVATE_KEY_PATH", "/secrets/id_ed25519")
    monkeypatch.setattr(settings, "SSH_KNOWN_HOSTS", None)
    monkeypatch.setattr(settings, "SSH_STRICT_HOST_KEY_CHECKING", False)
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm01"])
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    with pytest.raises(RuntimeError) as exc:
        SSHVMConnector()
    message = str(exc.value)
    assert "root SSH is forbidden" in message
    assert "SSH_KNOWN_HOSTS is required" in message
    assert "SSH_STRICT_HOST_KEY_CHECKING must be true" in message
