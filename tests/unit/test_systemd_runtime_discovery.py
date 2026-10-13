"""Contract and safety tests for technology-aware GFPAPI investigation."""
import base64
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from apps.context_service.evidence_collector import EvidenceCollector
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from domain.contracts.config import settings
from integrations.vm.runtime_discovery import parse_systemd_runtime, safe_absolute_path
from integrations.vm.dotnet_local_validator import (
    validate_encoded_file, safe_json_files, remote_file_listing_command,
)
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.vm.target_context import bind_vm_target, reset_vm_target


SYSTEMD = (
    "ExecStart={ path=/data/dotnet8/dotnet ; "
    "argv[]=/data/dotnet8/dotnet /data/gfp/gfpapi/GFP.Endpoints.API.dll ; "
    "ignore_errors=no }\n"
    "WorkingDirectory=/data/gfp/gfpapi\n"
    "FragmentPath=/etc/systemd/system/gfpapi.service\n"
    "Type=notify\nTimeoutStartUSec=1min\nRestart=on-failure\n"
    "Environment=ConnectionStrings__Default=TOP_SECRET_123\n"
)


def test_service_runtime_discovery_extracts_dotnet_from_systemd_without_secrets():
    got = parse_systemd_runtime(SYSTEMD, service="gfpapi")
    assert got["runtime"] == "dotnet"
    assert got["entrypoint"] == "/data/gfp/gfpapi/GFP.Endpoints.API.dll"
    assert got["publish_directory"] == "/data/gfp/gfpapi"
    assert got["unit_file"] == "/etc/systemd/system/gfpapi.service"
    assert got["service_type"] == "notify"
    assert got["timeout_start_usec"] == "1min"
    assert got["config_contents_exposed"] is False
    assert "TOP_SECRET_123" not in json.dumps(got)


@pytest.mark.parametrize("line", [
    "ExecStart={ path=/bin/sh ; argv[]=/bin/sh -c 'rm -rf /' ; ignore_errors=no }",
    "ExecStart={ path=/data/dotnet8/dotnet ; argv[]=/data/dotnet8/dotnet /data/../etc/secret.dll ; ignore_errors=no }",
    "ExecStart={ path=/data/dotnet8/dotnet ; argv[]=/data/dotnet8/dotnet /etc/secret.dll ; ignore_errors=no }",
])
def test_untrusted_unit_is_never_executed_or_accepted_as_publish_root(line):
    parsed = parse_systemd_runtime(line, service="gfpapi")
    assert parsed["runtime"] == "unknown"
    assert parsed["publish_directory"] is None


def test_dotnet_syntax_probe_reports_only_structure_no_application_secrets(tmp_path):
    publish = tmp_path / "gfpapi"
    publish.mkdir()
    (publish / "appsettings.json").write_text(
        '{"ApiKey":"SECRET_SHOULD_NOT_LEAK","ConnectionStrings":{"Main":"my-password"}}',
        encoding="utf-8",
    )
    (publish / "appsettings.Production.json").write_text(
        '{\n  "Logging": true,\n  "Bad": }\n', encoding="utf-8",
    )
    (publish / "GFP.Endpoints.API.runtimeconfig.json").write_text(
        '{"runtimeOptions":{"tfm":"net8.0"}}', encoding="utf-8"
    )
    rows = [
        validate_encoded_file(path.name, base64.b64encode(path.read_bytes()).decode())
        for path in sorted(publish.glob("*.json"))
    ]
    by_file = {row["file"]: row for row in rows}
    assert by_file["appsettings.json"]["status"] == "valid_json_syntax"
    assert by_file["appsettings.Production.json"]["status"] == "invalid_json_syntax"
    assert by_file["appsettings.Production.json"]["line"] == 3
    assert by_file["appsettings.Production.json"]["error_code"] == "json_value_missing"
    assert "SECRET_SHOULD_NOT_LEAK" not in json.dumps(rows)
    assert "my-password" not in json.dumps(rows)


def test_symlink_and_overflow_do_not_create_false_valid_configuration(tmp_path):
    publish = tmp_path / "published"
    publish.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret":"kept private"}', encoding="utf-8")
    (publish / "appsettings.json").symlink_to(outside)
    rows, partial = safe_json_files("appsettings.json\tl\n")
    assert rows == []
    assert partial is True
    assert "kept private" not in json.dumps(rows)
    with pytest.raises(ValueError):
        remote_file_listing_command("/etc")
    assert safe_absolute_path("/data/../etc/secret") is None


@pytest.mark.asyncio
async def test_connector_discovery_and_json_diagnostic_are_read_only(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    connector = SSHVMConnector()
    commands = []

    async def fake_run(target, command):
        assert target == "10.248.16.82"
        commands.append(command)
        if command.startswith("systemctl show "):
            return {"success": True, "stdout": SYSTEMD}
        if " find " in command:
            return {"success": True, "stdout": "appsettings.Production.json\tf\n"}
        if "base64 -w 0" in command:
            import base64
            return {"success": True, "stdout": base64.b64encode(
                b'{\n  "Logging": true,\n  "Bad": }\n'
            ).decode()}
        raise AssertionError("Unexpected command")
    monkeypatch.setattr(connector, "_run", fake_run)
    runtime = await connector.service_runtime_discovery("10.248.16.82", "gfpapi")
    assert runtime["runtime"] == "dotnet"
    status = await connector.dotnet_config_syntax("10.248.16.82", "gfpapi")
    assert status["success"] is True
    assert status["syntax_valid"] is False
    assert status["application_ready"] is None
    assert status["validated_scope"] == "json_syntax_only"
    assert status["config_contents_exposed"] is False
    assert len(commands) == 4
    assert all("python3 " not in c and "systemctl start" not in c and "rm -rf" not in c
               for c in commands)
    assert status["validator"] == "aiops-local-python-json-syntax-only"
    assert status["remote_python_required"] is False
    assert status["files"][0]["error_code"] == "json_value_missing"
    assert status["files"][0]["explanation_fa"]
    assert "Bad" not in json.dumps(status)
    with pytest.raises(PermissionError):
        await connector.service_runtime_discovery("10.248.16.82", "other-service")


@pytest.mark.asyncio
async def test_collector_escalates_unsupported_validator_to_dotnet_runtime(monkeypatch):
    monkeypatch.setattr(settings, "AIOPS_DYNAMIC_INVESTIGATION_ENABLED", True)
    vm_calls = []
    class VM:
        async def config_validate(self, target, service):
            vm_calls.append("config_validate")
            return {"success": True, "supported": False, "valid": None, "service": service}
        async def service_runtime_discovery(self, target, service):
            vm_calls.append("service_runtime_discovery")
            return {"success": True, "service": service, "runtime": "dotnet",
                    "entrypoint": "/data/gfp/gfpapi/GFP.Endpoints.API.dll",
                    "publish_directory": "/data/gfp/gfpapi"}
        async def dotnet_config_syntax(self, target, service):
            vm_calls.append("dotnet_config_syntax")
            return {"success": True, "runtime": "dotnet", "status": "syntax_valid",
                    "syntax_valid": True, "files": [{"file": "appsettings.json",
                    "status": "valid_json_syntax"}]}
    token = bind_vm_target("10.248.16.82")
    try:
        result = await EvidenceCollector(vm=VM()).collect_requested(
            "gfpapi", datetime.now(timezone.utc),
            [{"evidence_type": "telemetry", "reason": "configuration syntax validation",
              "preferred_source": "vm"}],
        )
    finally:
        reset_vm_target(token)
    assert vm_calls == ["config_validate", "service_runtime_discovery", "dotnet_config_syntax"]
    rows = result.get("evidence") or []
    actions = {row.get("raw_data", {}).get("diagnostic") for row in rows if isinstance(row, dict)}
    assert {"config_validate", "service_runtime_discovery", "dotnet_config_syntax"} <= actions


@pytest.mark.asyncio
async def test_dynamic_planner_grounds_cognia_and_operator_guidance_in_dotnet_evidence():
    state = {
        "service_name": "gfpapi", "incident_id": "gfp-incident",
        "knowledge_results": [], "coordination": {"missing_evidence": []},
        "context": {"evidence": [
            {"source": "vm_mcp", "reference": "unit-1",
             "raw_data": {"diagnostic": "service_runtime_discovery", "success": True,
                          "runtime": "dotnet", "service": "gfpapi",
                          "entrypoint": "/data/gfp/gfpapi/GFP.Endpoints.API.dll",
                          "publish_directory": "/data/gfp/gfpapi", "service_type": "notify"}},
            {"source": "vm_mcp", "reference": "json-1",
             "raw_data": {"diagnostic": "dotnet_config_syntax", "success": True,
                          "runtime": "dotnet", "service": "gfpapi",
                          "syntax_valid": False, "status": "invalid",
                          "files": [{"file": "appsettings.json", "line": 12,
                          "status": "invalid_json_syntax"}]}}
        ]},
    }
    query = DynamicInvestigationPlanner.search_query(
        service="gfpapi", evidence=state["context"]["evidence"], findings=[]
    )
    assert ".NET appsettings JSON syntax error" in query
    class LLM:
        async def generate_with_messages(self, *a, **kw):
            return SimpleNamespace(content='{"checks":["service_logs","dotnet_config_syntax"],"question":""}',
                                   finish_reason="stop")
    advice = await DynamicInvestigationPlanner.propose(state, adapter=LLM())
    assert advice["runtime_discovery"]["runtime"] == "dotnet"
    assert advice["runtime_discovery"]["syntax_valid"] is False
    assert advice["runtime_discovery"]["files"][0]["line"] == 12
    assert advice["operator_questions"]
    assert advice["execution_authority"] is False
    assert state.get("execution_request") is None
