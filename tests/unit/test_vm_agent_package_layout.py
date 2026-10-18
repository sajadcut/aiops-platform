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
    # Regression: a root-owned unreadable default used to crash systemd with
    # PermissionError('.env.example') when running as VM_AGENT_EXEC_USERNAME.
    assert 'chmod 0644 "$BUNDLE/.env.example"' in build
    assert 'chmod 0644 "$DST/.env.example"' in install
    assert 'chmod 0755 "$DST"' in install
    # Never widen permissions on the real credentials file.
    assert 'chmod 0644 "$DST/agent.env"' not in install
    assert 'install -o root -g root -m 0600 "$DST/agent.env.example" "$DST/agent.env"' in install
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


def test_installer_reapplies_traversable_mode_after_archive_copy(tmp_path):
    """Regression: cp -a SOURCE/. TARGET/ can restore a 0700 build directory."""
    import os
    import stat
    import subprocess

    source = tmp_path / "private-build"
    destination = tmp_path / "installed"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o755)
    # GNU cp -a preserves source directory mode on an EXISTING target.
    subprocess.run(["cp", "-a", str(source / "."), str(destination) + "/"],
                   check=True)
    # GNU cp archive destination mode handling varies with directory state
    # and version. Simulate the dangerous result explicitly when needed.
    destination.chmod(0o700)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700

    installer = (AGENT / "install.sh").read_text()
    archive_copy = installer.index('cp -a "$SRC/." "$DST/"')
    post_copy_chmod = installer.find('chmod 0755 "$DST"', archive_copy + 1)
    assert post_copy_chmod > archive_copy, (
        "Installer must restore destination traversal mode AFTER cp -a"
    )
    # Only the root directory changes; secret file modes must stay private.
    private_config = destination / "agent.env"
    private_config.write_text("VM_AGENT_BEARER_TOKEN=fake-secret\n")
    private_config.chmod(0o600)
    os.chmod(destination, 0o755)
    assert stat.S_IMODE(private_config.stat().st_mode) == 0o600


def test_installer_makes_private_pyinstaller_runtime_readable_without_widening_secrets(tmp_path):
    """A root/umask-077 build must work under the unprivileged systemd user."""
    import os
    import stat
    import subprocess

    root = tmp_path / "installed"
    internal = root / "_internal"
    nested = internal / "python"
    nested.mkdir(parents=True)
    lib = nested / "libpython3.12.so.1.0"
    lib.write_bytes(b"test shared object")
    lib.chmod(0o600)
    internal.chmod(0o700)
    nested.chmod(0o700)
    secret = root / "agent.env"
    secret.write_text("test-only-secret")
    secret.chmod(0o600)

    # Reproduce the narrow permission repair that install.sh applies.
    subprocess.run(["chmod", "-R", "a+rX", str(internal)], check=True)
    assert stat.S_IMODE(internal.stat().st_mode) == 0o755
    assert stat.S_IMODE(nested.stat().st_mode) == 0o755
    assert stat.S_IMODE(lib.stat().st_mode) == 0o644
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600

    install = (AGENT / "install.sh").read_text()
    assert '[[ -L "$DST/_internal" || ! -d "$DST/_internal" ]]' in install
    assert 'chmod -R a+rX "$DST/_internal"' in install
    assert 'chmod -R a+rX "$DST"' not in install
    assert install.index('chmod -R a+rX "$DST/_internal"') > install.index(
        'cp -a "$SRC/." "$DST/"'
    )


def test_root_guard_credentials_are_managed_by_installer_and_systemd():
    script = (AGENT / "install.sh").read_text()
    unit = (AGENT / "vmmcpagent.service").read_text()
    template = (AGENT / "agent.env.example").read_text()
    assert "openssl genpkey -algorithm Ed25519" in script
    assert '[[ ! -e "$GUARD_PRIVATE" && ! -e "$GUARD_PUBLIC" ]]' in script
    assert "Incomplete existing Root Guard keypair" in script
    assert "do not match" in script
    assert 'chmod 0600 "$GUARD_PRIVATE"' in script
    assert 'chmod 0644 "$GUARD_PUBLIC"' in script
    assert "LoadCredential=config-change-sign.pem:/etc/aiops/config-change-sign.pem" in unit
    assert "AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY=" not in template
