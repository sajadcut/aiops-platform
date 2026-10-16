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
    assert result["error"] == "config_validation_access_denied"
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
        if command.startswith("systemctl show "):
            config = "/etc/nginx/nginx.conf" if command.endswith("nginx") else "/etc/haproxy/haproxy.cfg"
            opt = "-c" if command.endswith("nginx") else "-f"
            return {"success": True, "exit_code": 0,
                    "stdout": f"{{ path=/usr/sbin/service ; argv[]=/usr/sbin/service {opt} {config} ; }}"}
        if command.startswith("sudo -k -S -p '' "):
            return {"success": True, "exit_code": 0, "stdout": "configuration ok", "stderr": ""}
        if command.startswith("sudo -n "):
            return {"success": False, "exit_code": 1, "stderr": "sudo: a password is required"}
        return {"success": False, "exit_code": 1, "stderr": "permission denied reading certificate"}

    monkeypatch.setattr(connector, "_run", fake_run)
    for service in ("nginx", "haproxy"):
        result = await connector.config_validate("10.100.6.199", service)
        assert result["success"] is True
        assert result["valid"] is True
    assert len(commands) == 8
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


@pytest.mark.asyncio
async def test_system_logs_fall_back_to_sudo_when_journal_denied(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    connector = SSHVMConnector()
    calls = []

    async def fake_run(target, command):
        calls.append(command)
        if command.startswith("journalctl "):
            return {"success": False, "exit_code": 1, "stderr": "permission denied"}
        if command.startswith("sudo -n journalctl "):
            return {"success": True, "exit_code": 0, "stdout": "service stopped by systemd", "stderr": ""}
        raise AssertionError("unexpected diagnostic command")

    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.system_logs("10.100.6.199", limit=20)
    assert result["success"] is True
    assert result["access_mode"] == "sudo"
    assert result["logs"] == ["service stopped by systemd"]
    assert len(calls) == 2



def test_systemd_execstart_config_discovery_and_syntax_error_line_are_safe():
    from integrations.vm.service_adapters import (
        config_check_for_path, discover_config_path, parse_config_diagnostic,
    )
    haproxy_exec = (
        "{ path=/usr/sbin/haproxy ; argv[]=/usr/sbin/haproxy -Ws "
        "-f /opt/grouppayment/haproxy.cfg -p /run/haproxy.pid ; ignore_errors=no ; }"
    )
    nginx_exec = (
        "{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx "
        "-c /etc/nginx/custom.conf -g 'daemon on; master_process on;' ; }"
    )
    assert discover_config_path("haproxy", haproxy_exec) == "/opt/grouppayment/haproxy.cfg"
    assert discover_config_path("nginx", nginx_exec) == "/etc/nginx/custom.conf"
    assert discover_config_path("nginx.service", nginx_exec) == "/etc/nginx/custom.conf"
    multi = ("{ path=/usr/sbin/haproxy ; argv[]=/usr/sbin/haproxy -Ws "
             "-f /etc/haproxy/main.cfg -f /etc/haproxy/extra.cfg ; }")
    assert discover_config_path("haproxy", multi) is None
    assert "/opt/grouppayment/haproxy.cfg" in config_check_for_path("haproxy", "/opt/grouppayment/haproxy.cfg")
    assert "-t -c /etc/nginx/custom.conf" in config_check_for_path("nginx", "/etc/nginx/custom.conf")

    parsed = parse_config_diagnostic(
        "nginx: [emerg] unknown directive 'bad_directive' in /etc/nginx/custom.conf:42"
    )
    assert parsed["config_file"] == "/etc/nginx/custom.conf"
    assert parsed["error_line"] == 42
    assert "unknown directive" in parsed["syntax_error"]
    proxy = parse_config_diagnostic(
        "[ALERT] config : parsing [/opt/grouppayment/haproxy.cfg:13] : unknown keyword 'bad'"
    )
    assert proxy["config_file"] == "/opt/grouppayment/haproxy.cfg"
    assert proxy["error_line"] == 13


def test_discovered_config_path_rejects_untrusted_shell_syntax():
    from integrations.vm.service_adapters import discover_config_path, config_check_for_path
    assert discover_config_path("haproxy", "argv[]=/usr/sbin/haproxy -f '/tmp/file.cfg;touch /tmp/hack' ;") is None
    assert discover_config_path("nginx", "argv[]=/usr/sbin/nginx -c ../../etc/nginx.conf ;") is None
    # No supplied path can insert a semicolon into the executed check command.
    assert ";touch" not in config_check_for_path("nginx", "/tmp/a.conf;touch /tmp/hack")
    assert "-t -c" not in config_check_for_path("nginx", "/tmp/a.conf;touch /tmp/hack")


@pytest.mark.asyncio
async def test_haproxy_config_validation_uses_systemd_override_and_reports_exact_error(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["haproxy"])
    connector = SSHVMConnector()
    commands = []

    async def fake_run(target, command):
        commands.append(command)
        if command.startswith("systemctl show "):
            return {"success": True,
                    "stdout": "{ path=/usr/sbin/haproxy ; argv[]=/usr/sbin/haproxy -Ws -f /opt/apps/haproxy.cfg ; }",
                    "exit_code": 0}
        return {
            "success": False, "exit_code": 1,
            "stderr": "[ALERT] config : parsing [/opt/apps/haproxy.cfg:23] : unknown keyword 'invalid_line'",
            "stdout": "",
        }

    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.config_validate("10.100.6.199", "haproxy")
    assert result["success"] is True
    assert result["supported"] is True
    assert result["valid"] is False
    assert result["config_file"] == "/opt/apps/haproxy.cfg"
    assert result["root_config_file"] == "/opt/apps/haproxy.cfg"
    assert result["error_line"] == 23
    assert "unknown keyword" in result["syntax_error"]
    assert "-f /opt/apps/haproxy.cfg" in commands[-1]


@pytest.mark.asyncio
async def test_unknown_haproxy_config_path_does_not_claim_default_file_is_valid(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["haproxy"])
    connector = SSHVMConnector()
    commands = []

    async def fake_run(target, command):
        commands.append(command)
        return {"success": True, "stdout": "argv[]=/usr/sbin/haproxy -Ws ;", "exit_code": 0}

    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.config_validate("10.100.6.199", "haproxy")
    assert result["supported"] is False
    assert result["valid"] is None
    assert result["detail"] == "running_config_path_unverified"
    assert len(commands) == 1  # No speculative check of /etc/haproxy/haproxy.cfg.


@pytest.mark.asyncio
async def test_unknown_service_config_is_advisory_not_a_generated_ssh_command(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    connector = SSHVMConnector()
    async def fake_run(target, command):
        assert command.startswith("systemctl show ")
        return {"success": True, "exit_code": 0,
                "stdout": "{ path=/usr/local/bin/gfpapi ; argv[]=/usr/local/bin/gfpapi --config=/opt/gfpapi/app.yml ; }"}
    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.config_validate("10.100.6.199", "gfpapi")
    assert result["success"] is True
    assert result["supported"] is False
    assert result["valid"] is None
    assert result["detail"] == "config_validation_adapter_unavailable"
    assert result["config_file"] == "/opt/gfpapi/app.yml"
    assert result["config_path_source"] == "systemd_execstart_unvalidated"



@pytest.mark.asyncio
async def test_config_permission_error_is_not_reported_as_syntax_failure(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    connector = SSHVMConnector()

    async def fake_run(target, command):
        if command.startswith("systemctl show "):
            return {"success": True, "stdout": "argv[]=/usr/sbin/nginx -c /etc/nginx/nginx.conf ;"}
        return {"success": False, "exit_code": 1,
                "stderr": "nginx: [emerg] open() /etc/nginx/secret.conf failed (13: Permission denied)"}

    async def fake_sudo(target, command):
        return {"success": False, "exit_code": 1,
                "stderr": "nginx: [emerg] open() /etc/nginx/secret.conf failed (13: Permission denied)"}

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(connector, "_sudo", fake_sudo)
    result = await connector.config_validate("10.100.6.199", "nginx")
    assert result["success"] is False
    assert result["valid"] is None
    assert result["error"] == "config_validation_access_denied"


@pytest.mark.asyncio
async def test_nginx_syntax_passes_despite_incidental_sudo_log_full_warning(monkeypatch):
    """No ENOSPC-based false veto when sudo actually returns code zero."""
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    connector = SSHVMConnector()

    async def run(target, command):
        if command.startswith("systemctl show "):
            return {"success": True, "exit_code": 0, "stdout": ""}
        return {
            "success": True, "exit_code": 0,
            "stdout": (
                "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
                "nginx: configuration file /etc/nginx/nginx.conf test is successful"
            ),
            "stderr": (
                "sudo: unable to write log file: /var/log/sudo.log: "
                "No space left on device\n"
            ),
        }
    monkeypatch.setattr(connector, "_run", run)
    outcome = await connector.config_validate("10.100.6.199", "nginx")
    assert outcome["success"] is True
    assert outcome["valid"] is True
    assert outcome["exit_code"] == 0
    assert outcome["nonfatal_warnings"] == ["sudo_audit_log_write_failed_enospc"]
    assert "No space left" not in outcome["detail"]


@pytest.mark.asyncio
async def test_nginx_start_attempt_not_blocked_by_nonfatal_sudo_log_warning(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    connector = SSHVMConnector()
    calls = []

    async def run(target, fixed_command, **kwargs):
        calls.append((target, fixed_command))
        return {
            "success": True, "exit_code": 0,
            "stderr": "sudo: unable to write log file: /var/log/sudo.log: No space left on device",
        }
    monkeypatch.setattr(connector, "_sudo", run)
    result = await connector.start_service("10.100.6.199", "nginx")
    assert result["success"] is True
    assert calls == [("10.100.6.199", "systemctl start nginx")]
