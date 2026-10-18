"""The installed VM MCP agent is fully colocated and safely configurable."""
from __future__ import annotations

from pathlib import Path

import pytest

from vmmcpagent import __main__ as entry
from vmmcpagent.connector import LocalVMConnector


ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "vmmcpagent"


def test_vm_agent_entrypoint_and_every_deployment_asset_in_own_directory():
    required = {
        "__init__.py", "__main__.py", "connector.py",
        "agent.env.example", "aiops-config-guard", "vmmcpagent.service",
        "sudoers.example", "build.sh", "install.sh", "README.md",
    }
    assert required <= {p.name for p in AGENT.iterdir()}
    from integrations.vm.local_agent_connector import LocalVMConnector as OldName
    assert OldName is LocalVMConnector
    from apps.vm_agent_runner import main as OriginalRunner
    assert OriginalRunner is entry.main
    assert (AGENT / "aiops-config-guard").read_bytes() == (
        ROOT / "scripts/vm/aiops-config-guard").read_bytes()


def test_agent_configuration_template_is_private_and_agent_specific():
    template = (AGENT / "agent.env.example").read_text()
    assert "VM_AGENT_TARGET=" in template
    assert "VM_AGENT_ALLOWED_SERVICES=" in template
    assert "VM_AGENT_BEARER_TOKEN=" in template
    assert "MCP_SERVER_PROVIDER=vm_agent" in template
    assert "SSH_ENABLED=False" in template
    assert "APP_ENV=production" in template
    assert "VM_AGENT_BIND_PORT=9105" in template
    assert "AIOPS_CONFIG_CANDIDATE_DIRECTORY=/data/aiopsvmagent/config-candidates" in template
    assert "LOG_DIR=/data/aiopsvmagent/logs" in template
    assert "VM_AGENT_BEARER_TOKEN=\n" in template
    assert "MCP_BEARER_TOKEN=\n" in template
    ignored = (ROOT / ".gitignore").read_text()
    assert "vmmcpagent/agent.env\n" in ignored


def test_entrypoint_reads_0600_agent_env_alongside_it(monkeypatch, tmp_path):
    home = tmp_path / "vmmcpagent"
    home.mkdir()
    configuration = home / "agent.env"
    configuration.write_text("VM_AGENT_TARGET=vm-colocated-01\nVM_AGENT_BIND_PORT=9405\n")
    configuration.chmod(0o600)
    monkeypatch.setattr(entry, "agent_directory", lambda: home)
    monkeypatch.chdir(ROOT)
    monkeypatch.delenv("VM_AGENT_TARGET", raising=False)
    monkeypatch.delenv("VM_AGENT_BIND_PORT", raising=False)
    assert entry.configure_agent_environment() == home
    import os
    assert os.environ["VM_AGENT_TARGET"] == "vm-colocated-01"
    assert os.environ["VM_AGENT_BIND_PORT"] == "9405"
    # python-dotenv modifies os.environ directly; restore cleanly.
    monkeypatch.delenv("VM_AGENT_TARGET", raising=False)
    monkeypatch.delenv("VM_AGENT_BIND_PORT", raising=False)


@pytest.mark.parametrize("permission", [0o644, 0o660, 0o640, 0o777])
def test_entrypoint_refuses_world_or_group_readable_secrets(monkeypatch, tmp_path, permission):
    configuration = tmp_path / "agent.env"
    configuration.write_text("VM_AGENT_BEARER_TOKEN=do-not-leak\n")
    configuration.chmod(permission)
    monkeypatch.setattr(entry, "agent_directory", lambda: tmp_path)
    with pytest.raises(RuntimeError, match="config_permissions"):
        entry.configure_agent_environment()


def test_entrypoint_refuses_symlink_agent_env(monkeypatch, tmp_path):
    actual = tmp_path / "credentials"
    actual.write_text("VM_AGENT_BEARER_TOKEN=do-not-leak\n")
    actual.chmod(0o600)
    (tmp_path / "agent.env").symlink_to(actual)
    monkeypatch.setattr(entry, "agent_directory", lambda: tmp_path)
    with pytest.raises(RuntimeError, match="config_symlink"):
        entry.configure_agent_environment()


def test_service_and_build_target_exact_same_agent_directory():
    unit = (AGENT / "vmmcpagent.service").read_text()
    build = (AGENT / "build.sh").read_text()
    install = (AGENT / "install.sh").read_text()
    assert "WorkingDirectory=/data/aiopsvmagent" in unit
    assert "EnvironmentFile=/data/aiopsvmagent/agent.env" in unit
    assert "ExecStart=/data/aiopsvmagent/vmmcpagent" in unit
    assert "vmmcpagent/__main__.py" in build
    assert 'cp "$ROOT/vmmcpagent/agent.env.example" "$BUNDLE/agent.env.example"' in build
    assert 'cp "$ROOT/.env.example" "$BUNDLE/.env.example"' in build
    assert "SRC/agent.env.example" in install
    assert 'DST="/data/aiopsvmagent"' in install
    assert '"$DST/config-candidates" "$DST/logs"' in install
    assert 'install -d -o "$ACTOR" -g "$ACTOR_GROUP" -m 0700' in install
    assert "10-execution-user.conf" in install
    assert "! -name 'config-candidates' ! -name 'logs'" in install
    assert "chmod 0600" in install
    assert "systemctl daemon-reload" in install
    assert "systemctl enable --now" not in install
    assert "VM_AGENT_BEARER_TOKEN" not in (AGENT / "vmmcpagent.service").read_text()
