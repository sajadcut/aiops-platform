"""Regression tests for explicit, bounded complete-file LLM repair."""
from __future__ import annotations

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from apps.incident_copilot import fallback_intent, public_result
from integrations.vm.full_config_llm_repair import (
    _candidate_preview, _parse_corrected, review_complete_config,
)
from integrations.vm.ssh_connector import SSHVMConnector


class ReplyModel:
    def __init__(self, corrected: str, finish_reason: str = "stop"):
        self.corrected = corrected
        self.finish_reason = finish_reason
        self.calls = []

    async def generate(self, prompt: str, **kwargs):
        self.calls.append((prompt, kwargs))
        return SimpleNamespace(
            content=json.dumps({"corrected_config": self.corrected}),
            finish_reason=self.finish_reason,
        )


@pytest.mark.asyncio
async def test_full_file_sent_once_to_model_and_complete_corrected_file_received(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://internal-llm.example")
    source = ("# one line\n" * 60 +
              "http {\n server {\n listen 8080; {\n }\n}\n" +
              "# password=DO_NOT_DISCLOSE_TO_MCP\n")
    corrected = source.replace("listen 8080; {", "listen 8080;")
    model = ReplyModel(corrected)
    result = await review_complete_config(
        base64.b64encode(source.encode()).decode(),
        service="nginx", path="/etc/nginx/nginx.conf",
        vendor_error='"listen" directive is not allowed here', model=model,
    )
    assert result["status"] == "llm_candidate_proposed"
    assert result["source_hash"] == hashlib.sha256(source.encode()).hexdigest()
    assert result["candidate_hash"] == hashlib.sha256(corrected.encode()).hexdigest()
    assert result["llm_received_complete_file"] is True
    assert result["llm_returned_complete_file"] is True
    assert len(model.calls) == 1
    payload = json.loads(model.calls[0][0])
    assert payload["complete_config"] == source
    assert result["validator_executed_on_proposal"] is False
    assert result["apply_eligible"] is False
    assert result["execution_authority"] is False
    assert "DO_NOT_DISCLOSE_TO_MCP" not in json.dumps(result)
    assert source not in json.dumps(result)
    assert corrected not in json.dumps(result)


@pytest.mark.asyncio
async def test_feature_off_never_reads_or_calls_model(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", False)
    model = ReplyModel("new")
    result = await review_complete_config(
        base64.b64encode(b"a\n").decode(), service="svc",
        path="/etc/svc/config.conf", model=model)
    assert result["status"] == "full_config_llm_not_enabled"
    assert not model.calls


@pytest.mark.asyncio
async def test_cleartext_remote_gateway_rejected_before_disclosure(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "http://10.0.0.99:8000")
    model = ReplyModel("new")
    result = await review_complete_config(
        base64.b64encode(b"a\n").decode(), service="svc",
        path="/etc/svc/config.conf", model=model)
    assert result["status"] == "trusted_llm_https_required"
    assert not model.calls


@pytest.mark.asyncio
async def test_oversize_file_not_truncated_or_submitted(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://internal-llm.example")
    model = ReplyModel("a\n")
    result = await review_complete_config(
        base64.b64encode(b"x" * (64 * 1024 + 1)).decode(),
        service="svc", path="/etc/svc/config.conf", model=model)
    assert result["status"] == "full_config_exceeds_model_budget"
    assert not model.calls


def test_micro_fix_rejects_unrelated_changes_even_if_model_returns_valid_json():
    source = (
        "http {\n"
        "    server {} \n"
        "    listen 8080;\n"
        "}\n"
    )
    minimal = source.replace("server {}", "server {")
    accepted = _candidate_preview(source, minimal, diagnostic_line=3)
    assert accepted["status"] == "llm_candidate_proposed"
    assert accepted["changed_line_numbers"] == [2]
    assert accepted["changed_line_count"] == 1
    assert accepted["redacted_changes"][0]["before"] != accepted["redacted_changes"][0]["after"]

    # Original bug: 12 reindented lines could pass because the grammar was
    # unchanged and _value_tokens discarded all whitespace.
    reindented = source.replace("    listen 8080;", "        listen 8080;")
    rejected = _candidate_preview(source, reindented, diagnostic_line=3)
    assert rejected["status"] == "llm_candidate_rejected"
    assert rejected["rejection_reason"] == "candidate_not_minimal_syntax_fix"

    reformatted_with_fix = minimal.replace(
        "    listen 8080;", "        listen 8080;"
    )
    rejected = _candidate_preview(source, reformatted_with_fix, diagnostic_line=3)
    assert rejected["rejection_reason"] == "candidate_changes_unrelated_bytes"

    # Three harmless-looking braces beyond the single typo are not allowed
    # even if every directive/port has the same token sequence.
    extra = source.replace("server {}", "server {{{{{{{")
    rejected = _candidate_preview(source, extra, diagnostic_line=3)
    assert rejected["status"] == "llm_candidate_rejected"
    assert rejected["rejection_reason"] == "candidate_not_minimal_syntax_fix"

    long_source = ("# unchanged\n" * 30 +
                   "http {\n" + "# untouched\n" * 20 +
                   "    server {} \n    listen 8080;\n}\n")
    unrelated = long_source.replace("http {", "http {};")
    rejected = _candidate_preview(long_source, unrelated, diagnostic_line=53)
    assert rejected["rejection_reason"] == "candidate_unrelated_to_validator_line"

    changed_value = source.replace("8080", "8081")
    assert _candidate_preview(source, changed_value)["status"] == "llm_candidate_rejected"


@pytest.mark.asyncio
async def test_llm_request_emphasizes_single_character_local_repair(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://trusted-llm.example")
    source = ("# header\n" * 99 + "server {}\nlisten 8080;\n")
    model = ReplyModel(source.replace("server {}", "server {"))
    result = await review_complete_config(
        base64.b64encode(source.encode()).decode(), service="nginx",
        path="/etc/nginx/nginx.conf",
        vendor_error='"listen" directive is not allowed here in /etc/nginx/nginx.conf:101',
        model=model,
    )
    assert result["status"] == "llm_candidate_proposed"
    payload = json.loads(model.calls[0][0])
    assert payload["vendor_error_line"] == 101
    assert payload["max_changed_lines"] == 3
    assert payload["max_syntax_char_edits"] == 3
    system = model.calls[0][1]["system_prompt"]
    assert "one-token typo repair" in system
    assert "not a configuration cleanup" in system
    assert "Preserve EVERY other byte" in system


def test_changed_secret_line_and_whole_file_rewrite_rejected():
    original = 'global\npassword=keep\nlisten 8080; {\n'
    assert _candidate_preview(original, original.replace("keep", "other"))[
        "rejection_reason"] == "candidate_changes_sensitive_line"
    rewritten = "".join(f"different_{i}\n" for i in range(100))
    assert _candidate_preview(original, rewritten)["status"] == "llm_candidate_rejected"


def test_response_parser_accepts_json_fence_but_not_partial_file():
    assert _parse_corrected('```json\n{"corrected_config":"hello\\n"}\n```') == "hello\n"
    assert _parse_corrected('{"corrected_config":123}') is None
    assert _candidate_preview("abc\n", "abc")["status"] == "llm_candidate_rejected"


@pytest.mark.asyncio
async def test_connector_resolves_only_verified_path_and_never_returns_source(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://internal-llm.example")
    connector = SSHVMConnector()
    monkeypatch.setattr(connector, "_validate_target", lambda _: None)
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    async def validate(target, service):
        return {"supported": False, "config_file": None}
    async def discover(target, service):
        return {"files": [
            {"path": "/etc/svc/not-verified.conf", "verified_exists": False},
            {"path": "/etc/svc/main.conf", "verified_exists": True},
        ]}
    source = b"frontend test\n"
    commands = []
    async def run(target, command):
        commands.append(command)
        return {"success": True, "stdout": base64.b64encode(source).decode()}
    async def model_review(encoded, **kw):
        assert base64.b64decode(encoded) == source
        return {"success": True, "status": "llm_candidate_proposed",
                "candidate_hash": "a" * 64, "config_file": kw["path"]}
    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "service_config_discovery", discover)
    monkeypatch.setattr(connector, "_run", run)
    monkeypatch.setattr(repair, "review_complete_config", model_review)
    # ssh_connector imports helper inside method; the module monkeypatch applies.
    result = await connector.service_config_llm_repair("192.0.2.1", "svc")
    assert result["status"] == "llm_candidate_proposed"
    assert result["config_file"] == "/etc/svc/main.conf"
    assert len(commands) == 1 and "base64 -w 0" in commands[0]
    assert source.decode() not in json.dumps(result)


def test_incident_chat_routes_only_explicit_full_file_request_and_filters_raw():
    assert fallback_intent("فایل کانفیگ کامل رو بده به LLM اصلاح کن") == "service_config_llm_repair"
    assert fallback_intent("config syntax check") != "service_config_llm_repair"
    public = public_result("service_config_llm_repair", {
        "success": True, "service": "nginx", "target": "192.0.2.1",
        "status": "llm_candidate_proposed", "candidate_hash": "a" * 64,
        "source": "password=DO_NOT_LEAK", "corrected_config": "password=LEAK",
    })
    assert public["diagnostic"] == "service_config_llm_repair"
    assert "DO_NOT_LEAK" not in json.dumps(public)
    assert "LEAK" not in json.dumps(public)


def test_incident_banner_offers_deliberate_full_file_llm_preview():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = (root / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert 'data-config-preview="full-llm"' in script
    assert "window.confirm(" in script
    assert "service_config_llm_repair:" in script
    assert "متن کامل فایل تنظیمات" in script
    assert "fullLLMButton" in script
