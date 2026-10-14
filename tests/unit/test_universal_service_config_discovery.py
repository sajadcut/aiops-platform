"""Contract for systemd + LLM-assisted configuration discovery and safe review."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest

from apps.context_service.llm_identity import detect_operational_unknowns
from apps.incident_copilot import fallback_intent
from integrations.vm.general_config_review import (
    local_config_review, remote_config_read_command,
)
from integrations.vm.runtime_discovery import parse_systemd_runtime


def _unit(command):
    return ("ExecStart={ path=/usr/bin/java ; argv[]=" + command +
            " ; ignore_errors=no }\n"
            "WorkingDirectory=/opt/tomcat\n"
            "FragmentPath=/etc/systemd/system/tomcat.service\nType=simple\n")


def test_tomcat_catalina_base_is_path_hypothesis_not_validation():
    x = parse_systemd_runtime(_unit(
        "/usr/bin/java -Dcatalina.base=/opt/apache-tomcat-10 "
        "-Ddb.password=NEVER_LEAK_PASSWORD org.apache.catalina.startup.Bootstrap start"
    ), service="tomcat-custom")
    assert x["runtime"] == "tomcat"
    paths = {row["path"] for row in x["config_candidates"]}
    assert "/opt/apache-tomcat-10/conf/server.xml" in paths
    assert "/opt/apache-tomcat-10/conf/context.xml" in paths
    assert all(row["verified_exists"] is False for row in x["config_candidates"])
    assert all(row["content_validated"] is False for row in x["config_candidates"])
    assert "NEVER_LEAK_PASSWORD" not in json.dumps(x)


def test_java_spring_config_file_comes_from_unit_flag_not_model_guesses():
    x = parse_systemd_runtime(_unit(
        "/usr/bin/java -jar /opt/apps/pay.jar "
        "-Dspring.config.location=file:/srv/payment/application.yaml "
        "--config-file=/etc/myapp/custom.json -Dapi.token=secret-key"
    ), service="paymentd")
    assert x["runtime"] == "java"
    paths = {row["path"] for row in x["config_candidates"]}
    assert "/srv/payment/application.yaml" in paths
    assert "/etc/myapp/custom.json" in paths
    assert "/opt/apps/pay.jar" not in paths
    assert "secret-key" not in json.dumps(x)


def test_unknown_systemd_runtime_requires_followup_not_claimed_absence():
    x = parse_systemd_runtime(
        "ExecStart={ path=/opt/special/bin/server ; argv[]=/opt/special/bin/server "
        "; ignore_errors=no }\nFragmentPath=/etc/systemd/system/special.service",
        service="special",
    )
    assert x["runtime"] == "unknown"
    assert x["config_candidates"] == []
    unknowns = detect_operational_unknowns([
        {"source": "vm_mcp", "reference": "id-1", "raw_data": {
            "diagnostic": "service_runtime_discovery", "success": True,
            "service": "special", "runtime": "unknown", "config_candidates": [],
        }},
        {"source": "vm_mcp", "reference": "id-2", "raw_data": {
            "diagnostic": "service_config_discovery", "success": True,
            "service": "special", "status": "no_systemd_config_candidates", "files": [],
        }},
    ])
    topics = {u["topic"] for u in unknowns}
    assert "service_configuration_discovery" in topics
    assert "service_configuration_location" in topics
    assert all("evidence_refs" in u for u in unknowns)


@pytest.mark.parametrize("path", [
    "/etc/shadow", "/etc/ssh/ssh_host_rsa_key", "/etc/nginx/../passwd",
    "/tmp/app.json", "/run/secrets/config.json", "/etc/ssl/private/secret.conf",
    "/etc/a.conf; rm -rf /", "/srv/app/not-a-config.txt",
])
def test_config_review_rejects_unverified_or_sensitive_path(path):
    with pytest.raises(ValueError):
        remote_config_read_command(path)


def test_generic_remote_review_only_reads_bounded_fixed_file():
    cmd = remote_config_read_command("/etc/haproxy/haproxy.cfg")
    assert "stat -c %s" in cmd and "readlink -f" in cmd
    assert "base64 -w 0" in cmd and "test ! -L" in cmd
    assert "262144" in cmd
    for forbidden in ("python", "sudo", "sed -i", "mv ", "cp ", "rm ", "chown ", "chmod "):
        assert forbidden not in cmd


def test_json_secret_safe_trailing_comma_correction_only_on_worker():
    raw = '{"apiToken":"sensitive-secret-value", "note":"comma,} inside string", "enabled":true,}'
    result = local_config_review(
        base64.b64encode(raw.encode()).decode(),
        path="/srv/app/application.json",
    )
    assert result["status"] == "candidate_proposed"
    assert result["proposed_change"] == "remove_trailing_json_comma"
    assert result["candidate_hash"] and result["source_hash"]
    assert result["candidate_hash"] != result["source_hash"]
    assert result["validation_status"] == "FORMAT_CANDIDATE_VALID_ONLY"
    assert result["validator_executed_on_proposal"] is True
    assert result["apply_eligible"] is False
    assert result["execution_authority"] is False
    for value in ("sensitive-secret-value", "comma,} inside string", "apiToken"):
        assert value not in json.dumps(result)


@pytest.mark.parametrize("xml,expected", [
    ('<?xml version="1.0"?><Server><Service/></Server>', "FORMAT_VALID"),
    ('<Server><Service></Server>', "FORMAT_INVALID"),
    ('<!DOCTYPE Server [<!ENTITY x SYSTEM "file:///etc/passwd">]><Server/>', "FORMAT_UNVERIFIED"),
])
def test_tomcat_xml_format_check_is_not_service_health(xml, expected):
    result = local_config_review(
        base64.b64encode(xml.encode()).decode(),
        path="/opt/tomcat/conf/server.xml",
    )
    assert result["validation_status"] == expected
    assert result["candidate_hash"] is None
    assert result["apply_eligible"] is False
    assert "file:///etc/passwd" not in json.dumps(result)


def test_haproxy_vendor_validation_is_not_faked_by_file_read():
    result = local_config_review(
        base64.b64encode(b"frontend ingress\n bind :80\n").decode(),
        path="/etc/haproxy/haproxy.cfg", validator_error_line=2,
    )
    assert result["status"] == "file_observed"
    assert result["validation_status"] == "UNVERIFIED"
    assert result["candidate_hash"] is None
    assert result["current_excerpt"]
    assert "bind :80" not in json.dumps(result)


def test_incident_chat_supports_general_config_discovery_and_review():
    assert fallback_intent("service_config_discovery: فایل کانفیگ همین سرویس را پیدا کن") == "service_config_discovery"
    assert fallback_intent("service_config_review: فایل کانفیگ این سرویس را بررسی کن") == "service_config_review"


@pytest.mark.asyncio
async def test_llm_research_is_required_for_unknown_config_but_cannot_verify_a_guess(monkeypatch):
    from types import SimpleNamespace
    from apps.context_service.llm_identity import consult_operational_unknowns
    from domain.contracts.config import settings

    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai-compatible")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://llm.invalid/v1")
    monkeypatch.setattr(settings, "LLM_MODEL", "example-model")
    gap = {
        "topic": "service_configuration_discovery", "subject": "custom-tomcat",
        "reason": "Unit-derived path not confirmed", "evidence_refs": ["vm:unit:1"],
    }

    class LLM:
        async def generate_with_messages(self, messages, **kwargs):
            assert kwargs["stage"] == "operational_unknown_guidance"
            assert "service_config_discovery" in messages[0]["content"]
            assert "Unit-derived path not confirmed" in messages[1]["content"]
            return SimpleNamespace(
                content=json.dumps({"items": [{
                    "topic": gap["topic"], "subject": gap["subject"],
                    "explanation": "Tomcat usually resolves Catalina base/conf/server.xml",
                    "validation_approach": "Check registered read-only service_config_discovery and vendor docs",
                    "uncertainty": "Path presence and effective config not confirmed",
                }]}),
                finish_reason="stop",
            )

    result = await consult_operational_unknowns(unknowns=[gap], adapter=LLM())
    assert result["status"] == "suggested"
    assert result["items"][0]["verified"] is False
    assert result["items"][0]["source"] == "llm_advisory"
    assert result["execution_authority"] is False
    assert result["counts_as_evidence"] is False
    assert result["config_validation_passed"] is False


@pytest.mark.asyncio
async def test_vm_mcp_verifies_tomcat_config_paths_without_running_unit_argv(monkeypatch):
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = SSHVMConnector()
    calls = []
    async def discover(target, service):
        return {
            "success": True, "runtime": "tomcat",
            "unit_file": "/etc/systemd/system/tomcat.service",
            "config_candidates": [{
                "path": "/opt/tomcat/conf/server.xml",
                "source": "systemd_catalina_base",
            }],
            "working_directory": "/opt/tomcat",
        }
    async def read(target, command):
        calls.append(command)
        return {"success": True, "stdout": ""}
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    monkeypatch.setattr(connector, "service_runtime_discovery", discover)
    monkeypatch.setattr(connector, "_run", read)
    res = await connector.service_config_discovery("192.0.2.10", "custom-tomcat")
    assert res["success"] is True
    assert res["status"] == "verified_candidates"
    assert res["files"][0]["path"] == "/opt/tomcat/conf/server.xml"
    assert res["files"][0]["verified_exists"] is True
    assert res["files"][0]["content_validated"] is False
    assert "readlink -f" in calls[0]
    assert all("python" not in command and "java " not in command for command in calls)
    assert res["execution_authority"] is False


@pytest.mark.asyncio
async def test_custom_unit_workdir_inventory_excludes_secret_file_names(monkeypatch):
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = SSHVMConnector()
    async def unit(target, service):
        return {"success": True, "runtime": "unknown",
                "config_candidates": [], "working_directory": "/srv/custom-service"}
    commands = []
    async def read(target, command):
        commands.append(command)
        if "find " in command:
            return {"success": True, "stdout":
                    "/srv/custom-service/config/app.yaml\n"
                    "/srv/custom-service/password.properties\n"
                    "/etc/shadow\n"
                    "/srv/custom-service/config/service.xml"}
        return {"success": True}
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    monkeypatch.setattr(connector, "service_runtime_discovery", unit)
    monkeypatch.setattr(connector, "_run", read)
    result = await connector.service_config_discovery("192.0.2.10", "special")
    names = [f["path"] for f in result["files"]]
    assert names == ["/srv/custom-service/config/app.yaml",
                     "/srv/custom-service/config/service.xml"]
    assert all(row["verified_exists"] is True for row in result["files"])
    assert all(row["content_validated"] is False for row in result["files"])
    assert all("systemctl start" not in cmd and "sudo" not in cmd for cmd in commands)
    assert "password" not in json.dumps(result)


@pytest.mark.asyncio
async def test_generic_review_uses_only_verified_file_and_never_returns_ssh_raw_content(monkeypatch):
    from integrations.vm.ssh_connector import SSHVMConnector
    connector = SSHVMConnector()
    source = '<Server password="PRIVATE_VALUE"><Service/></Server>'
    async def validate(target, service):
        return {"success": True, "supported": False, "valid": None}
    async def discovery(target, service):
        return {"success": True, "status": "verified_candidates",
                "runtime": "tomcat", "files": [{
                    "path": "/opt/tomcat/conf/server.xml",
                    "verified_exists": True,
                }]}
    async def read(target, command):
        assert "head -c" in command and "base64" in command
        return {"success": True, "stdout":
                base64.b64encode(source.encode()).decode()}
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "service_config_discovery", discovery)
    monkeypatch.setattr(connector, "_run", read)
    review = await connector.service_config_review("192.0.2.10", "tomcat-custom")
    assert review["status"] == "file_observed"
    assert review["validation_status"] == "FORMAT_VALID"
    assert review["execution_authority"] is False
    assert review["apply_eligible"] is False
    assert review["candidate_hash"] is None
    assert review["path_source"] == "verified_systemd_candidate"
    assert "PRIVATE_VALUE" not in json.dumps(review)
    assert "password" not in json.dumps(review)
