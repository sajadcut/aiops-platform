"""Evidence-backed Nginx file inspection without remote Python or secret leakage."""
from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from apps.incident_copilot import (
    fallback_intent, nginx_inspection_answer, public_result,
)
from integrations.vm.nginx_config_inspection import (
    nginx_inspection_command, parse_nginx_inspection,
)
from integrations.vm.ssh_connector import SSHVMConnector


def sample_protocol():
    return (
        "FILE\t/etc/nginx/nginx.conf\t/etc/nginx/nginx.conf\t1450\n"
        "ROW\t7\thttp\nROW\t8\tinclude\n"
        "FILE\t/etc/nginx/sites-enabled/app\t/etc/nginx/sites-available/app\t990\n"
        "ROW\t103\tbrace_open\n"
        "ROW\t104\tproxy_pass\n"
        "END\t2\n"
    )


def test_nginx_parser_keeps_structural_lines_and_symlink_alias_but_never_values():
    rows = parse_nginx_inspection(sample_protocol())
    assert rows["status"] == "inspected"
    assert rows["inspected_count"] == 2
    assert rows["files"][1]["source"] == "/etc/nginx/sites-enabled/app"
    assert rows["files"][1]["resolved"] == "/etc/nginx/sites-available/app"
    assert rows["files"][1]["directives"][0] == {"line": 103, "directive": "brace_open"}
    assert rows["config_contents_exposed"] is False
    assert rows["configuration_valid"] is None
    assert rows["execution_authority"] is False


def test_untrusted_stdout_cannot_add_private_paths_or_config_values():
    output = (
        "FILE\t/etc/shadow\t/etc/shadow\t100\n"
        "ROW\t1\tpassword=very-secret\n"
        "FILE\t/etc/nginx/sites-enabled/app\t/etc/nginx/sites-available/app\t10\n"
        "ROW\t1\tpassword\n"
        "ROW\t2\tssl_certificate_key\n"
        "ROW\t3\tproxy_pass https://token@example\n"
        "FILE\t/etc/nginx/sites-enabled/bad\\tpath\t/etc/nginx/sites-available/bad\t10\n"
        "END\t2\n"
    )
    safe = parse_nginx_inspection(output)
    assert safe["inspected_count"] == 1
    assert safe["files"][0]["directives"] == [
        {"line": 2, "directive": "ssl_certificate_key"},
    ]
    assert "very-secret" not in json.dumps(safe)
    assert "token@example" not in json.dumps(safe)


@pytest.mark.parametrize("path", [
    "/etc/passwd", "/root/.ssh/id_rsa", "/etc/nginx/../shadow",
    "/etc/nginx/nginx.conf;cat /etc/shadow",
])
def test_nginx_command_does_not_accept_arbitrary_paths(path):
    command = nginx_inspection_command(path, 103)
    arguments = shlex.split(command)
    assert arguments[:2] == ["sh", "-c"]
    assert arguments[3] == "--"
    assert arguments[4] == "/__not_an_nginx_file__"
    assert not any(part in command for part in (
        "python3 -", "chmod ", "chown ", "sudo ", "systemctl reload",
        "sed -i ", "rm -rf", "cat /etc/shadow",
    ))


def test_remote_shell_inspection_is_secret_safe_on_fixture_with_symlink(tmp_path):
    root = tmp_path / "nginx"
    (root / "conf.d").mkdir(parents=True)
    (root / "sites-enabled").mkdir()
    (root / "sites-available").mkdir()
    (root / "nginx.conf").write_text(
        'events { worker_connections 256; }\n'
        'http { include /etc/nginx/sites-enabled/*; }\n'
        'proxy_pass https://real-secret-token.example/path;\n',
        encoding="utf-8",
    )
    (root / "sites-available" / "app").write_text(
        'server {\nlisten 443 ssl;\n'
        'ssl_certificate_key /really/private/key.pem;\n'
        'proxy_set_header Authorization "SECRET_AUTH_ABC";\n}\n',
        encoding="utf-8",
    )
    (root / "sites-enabled" / "app").symlink_to("../sites-available/app")
    outside = tmp_path / "outside.conf"
    outside.write_text("SECRET_DO_NOT_FOLLOW\n", encoding="utf-8")
    (root / "conf.d" / "escape.conf").symlink_to(outside)
    # The script is immutable in production. Redirect its *fixed fixture roots*
    # only within this local test; no target machine needs Python installed.
    parts = shlex.split(nginx_inspection_command("/etc/nginx/nginx.conf", 3))
    script = parts[2].replace("/etc/nginx/", str(root) + "/")
    script = script.replace("/usr/local/nginx/conf/", str(root) + "/not-present/")
    check = subprocess.run(
        ["sh", "-c", script, "--", str(root / "nginx.conf"), "3"],
        capture_output=True, text=True, timeout=8, check=True,
    )
    assert "FILE\t" + str(root / "nginx.conf") in check.stdout
    assert "FILE\t" + str(root / "sites-enabled/app") in check.stdout
    assert "proxy_pass" in check.stdout
    assert "ssl_certificate_key" in check.stdout
    assert "Authorization" not in check.stdout
    assert "SECRET_AUTH_ABC" not in check.stdout
    assert "real-secret-token" not in check.stdout
    assert "SECRET_DO_NOT_FOLLOW" not in check.stdout
    assert str(outside) not in check.stdout


@pytest.mark.asyncio
async def test_connector_uses_only_compiler_path_and_returns_redacted_file_inventory(monkeypatch):
    connector = SSHVMConnector()
    monkeypatch.setattr(connector, "_validate_service", lambda service: None)
    called = []

    async def validate(target, service):
        return {
            "success": True, "supported": True, "valid": False,
            "config_file": "/etc/nginx/sites-enabled/app", "error_line": 103,
            "syntax_error": 'unexpected "{" in /etc/nginx/sites-enabled/app:103',
            "root_config_file": "/etc/nginx/nginx.conf",
        }

    async def run(target, command):
        called.append((target, command))
        return {"success": True, "stdout": sample_protocol(),
                "stderr": "should_not_be_exported_SECRET"}

    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "_run", run)
    result = await connector.nginx_config_inspect("10.248.16.82", "nginx")
    assert result["success"] is True
    assert result["validator_status"] == "invalid"
    assert result["validator_error_line"] == 103
    assert len(result["files"]) == 2
    assert len(called) == 1
    assert called[0][0] == "10.248.16.82"
    assert shlex.split(called[0][1])[4] == "/etc/nginx/sites-enabled/app"
    assert "should_not_be_exported_SECRET" not in json.dumps(result)
    assert result["execution_authority"] is False

    refused = await connector.nginx_config_inspect("10.248.16.82", "haproxy")
    assert refused["supported"] is False
    assert len(called) == 1


def test_incident_copilot_requests_file_tool_instead_of_generic_validator():
    for prompt in (
        "فایل nginx.conf رو بخون", "برو فایل‌های sites-enabled رو ببین",
        "لیست فایل کانفیگ nginx رو بیار", "inspect nginx files",
    ):
        assert fallback_intent(prompt) == "nginx_config_inspect"
    assert fallback_intent("nginx -t کانفیگ خطا داره؟") == "config_validate"


def test_incident_copilot_scrubs_nested_mcp_file_values():
    payload = {
        "success": True, "status": "inspected",
        "validator_status": "invalid", "validator_error_line": 103,
        "files": [
            {"source": "/etc/nginx/nginx.conf", "resolved": "/etc/nginx/nginx.conf",
             "directives": [
                 {"line": 103, "directive": "server"},
                 {"line": 104, "directive": "password=SECRET_KEY_VALUE"},
             ],
             "secret": "SECRET_KEY_VALUE",
            },
            {"source": "/root/.ssh/id_rsa", "resolved": "/root/.ssh/id_rsa",
             "directives": [{"line": 1, "directive": "server"}]},
        ],
        "raw_config": "SECRET_KEY_VALUE",
    }
    result = public_result("nginx_config_inspect", payload)
    assert result["files"][0]["directives"] == [{"line": 103, "directive": "server"}]
    assert len(result["files"]) == 1
    assert "SECRET_KEY_VALUE" not in json.dumps(result)


def test_read_result_cannot_be_spun_as_no_filesystem_access():
    payload = public_result("nginx_config_inspect", {
        "success": True, "status": "inspected",
        "validator_status": "invalid", "validator_error_line": 103,
        "validator_error_file": "/etc/nginx/nginx.conf",
        "validator_error": 'unexpected "{"',
        "files": [{"source": "/etc/nginx/nginx.conf",
                   "resolved": "/etc/nginx/nginx.conf",
                   "directives": [{"line": 103, "directive": "brace_open"}]}],
    })
    answer = nginx_inspection_answer(payload)
    assert "VM MCP" in answer
    assert "nginx.conf" in answer
    assert "103" in answer
    assert "دسترسی ندارم" not in answer


@pytest.mark.asyncio
async def test_incident_chat_explicit_file_read_overrides_model_no_access(monkeypatch):
    import apps.api.incident_chat as api

    incident_id = UUID("11111111-1111-4111-8111-111111111111")
    calls = []

    class Session:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return False
    class Audit:
        def __init__(self, db):
            pass
        async def list(self, incident_id, limit):
            return []
        async def append(self, event):
            calls.append(("audit", event.get("event_type")))
    async def scope(db, iid):
        return SimpleNamespace(service="nginx"), {
            "state": {"context": {}}
        }, [{
            "source": "vm_mcp", "reference": "vm-status-1",
            "raw_data": {"diagnostic": "service_status", "service": "nginx",
                         "target": "10.248.16.82", "success": True},
        }]
    async def brief(db, iid):
        return {"incident_summary": {"service": "nginx"}}
    async def model(*args, **kwargs):
        calls.append(("model", kwargs.get("observation") is not None))
        return {"intent": "answer", "answer": "من دسترسی به فایل‌سیستم ندارم.",
                "model_status": "structured"}
    async def read(action, binding):
        calls.append(("tool", action))
        return public_result("nginx_config_inspect", {
            "success": True, "status": "inspected",
            "validator_status": "invalid", "validator_error_line": 103,
            "validator_error_file": "/etc/nginx/nginx.conf",
            "files": [{"source": "/etc/nginx/nginx.conf",
                       "resolved": "/etc/nginx/nginx.conf",
                       "directives": [{"line": 103, "directive": "brace_open"}]}],
        })
    async def append(*args, **kwargs):
        calls.append(("turn", kwargs["role"]))
        return "turn-1"

    monkeypatch.setattr(api, "AsyncSessionLocal", Session)
    async def isolated_followup(*args, **kwargs):
        return {"status": "isolated_test_no_database", "reassessed": False}
    monkeypatch.setattr(api, "persist_and_reassess", isolated_followup)
    monkeypatch.setattr(api, "_scope", scope)
    monkeypatch.setattr(api, "PostgreSQLAuditStore", Audit)
    monkeypatch.setattr(api, "load_decision_brief_for_incident", brief)
    monkeypatch.setattr(api, "llm_plan", model)
    monkeypatch.setattr(api, "vm_read", read)
    monkeypatch.setattr(api, "append_turn", append)
    outcome = await api.incident_chat_message(
        incident_id,
        api.IncidentChatMessage(message="فایل nginx.conf رو بخون و خطا رو بگو"),
        identity=SimpleNamespace(subject="sre"),
    )
    assert ("tool", "nginx_config_inspect") in calls
    assert outcome["kind"] == "tool_result"
    assert outcome["model_status"] == "structured"
    assert outcome["answer_basis"] == "live_mcp"
    assert "nginx.conf" in outcome["message"] and "103" in outcome["message"]
    assert "دسترسی به فایل‌سیستم ندارم" not in outcome["message"]
