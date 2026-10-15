"""Tests for universal value-free config analysis and two LLM review passes."""
import base64
import hashlib
import json

import pytest

from apps.config_syntax_llm import assess_service_syntax, sanitized_projection
from apps.incident_copilot import public_result
from integrations.llm.base import LLMResponse
from integrations.vm.general_config_review import local_config_review
from integrations.vm.llm_syntax_projection import syntax_projection


@pytest.mark.parametrize("ext,text", [
    ("json", '{"password":"NEVER_SEND_THIS_VALUE","enabled":true,}\n'),
    ("yaml", "api_key: VERY_PRIVATE_VALUE\nlisten: server\n"),
    ("properties", "jdbc.password=NEVER_SEND_THIS_VALUE\n"),
    ("conf", 'server_name "NEVER_SEND_THIS_VALUE"; # DO_NOT_EXPOSE_COMMENT\n'),
    ("cfg", "frontend secret_gateway\n  bind 10.0.0.1:8443\n"),
    ("ini", "password=NEVER_SEND_THIS_VALUE\n"),
    ("xml", '<Server password="NEVER_SEND_THIS_VALUE"/>\n'),
])
def test_grammar_projection_does_not_leak_values(ext, text):
    projected = syntax_projection(text, extension=ext)
    raw = json.dumps(projected)
    assert "NEVER_SEND_THIS_VALUE" not in raw
    assert "VERY_PRIVATE_VALUE" not in raw
    assert "DO_NOT_EXPOSE_COMMENT" not in raw
    assert sanitized_projection(projected) is not None
    assert projected["representation"] == "value_free_syntax_tokens"
    assert all("line" in row and "indent" in row for row in projected["lines"])


def test_json_trailing_comma_can_be_projected_for_both_llm_passes():
    source = b'{"password":"HIDDEN","enabled":true,}\n'
    review = local_config_review(
        base64.b64encode(source).decode(), path="/opt/service/appsettings.json",
    )
    assert review["status"] == "candidate_proposed"
    assert review["syntax_projection"]
    assert review["candidate_syntax_projection"]
    assert "HIDDEN" not in json.dumps(review["syntax_projection"])
    assert "HIDDEN" not in json.dumps(review["candidate_syntax_projection"])
    assert review["source_hash"] == hashlib.sha256(source).hexdigest()
    assert review["apply_eligible"] is False


def test_public_result_forbids_raw_and_malicious_config_content():
    valid = syntax_projection("frontend a\n    bind *:443\n", extension="cfg")
    event = public_result("service_config_review", {
        "success": True, "service": "haproxy",
        "config_file": "/etc/haproxy/haproxy.cfg",
        "syntax_projection": valid,
        "candidate_syntax_projection": {
            "representation": "value_free_syntax_tokens",
            "lines": [{"line": 1, "indent": 0, "syntax": "password=raw-secret"}],
        },
        "raw_file": "password=NEVER_FORWARD",
    })
    assert "NEVER_FORWARD" not in json.dumps(event)
    assert "raw_file" not in event
    assert event["syntax_projection"]["lines"]
    assert "candidate_syntax_projection" not in event


@pytest.mark.asyncio
async def test_two_model_passes_cannot_approve_or_validate_a_configuration():
    prompts = []
    class Model:
        async def generate(self, prompt, **kwargs):
            prompts.append((prompt, kwargs))
            if len(prompts) == 1:
                answer = {"error_kind": "extra_delimiter", "repair_kind": "remove_token",
                          "line": 2, "reason": "possible extra punctuation",
                          "suggestion": "inspect the second line"}
            else:
                answer = {"error_kind": "not_enough_information", "repair_kind": "none",
                          "line": None, "reason": "masked content is insufficient",
                          "suggestion": "run vendor validator"}
            return LLMResponse(content=json.dumps(answer), model="test")

    original = syntax_projection("global\nfrontend example\n", extension="cfg")
    candidate = syntax_projection("global\nfrontend example\n", extension="cfg")
    result = await assess_service_syntax(original, candidate, model=Model())
    assert result["status"] == "reviewed_twice"
    assert len(prompts) == 2
    assert "FIRST REVIEW" in prompts[0][0]
    assert "SECOND INDEPENDENT REVIEW" in prompts[1][0]
    assert result["candidate_projection_available"] is True
    assert result["approval_eligible"] is False
    assert result["execution_authority"] is False
    assert result["model_validated"] is False
    assert result["vendor_validated"] is False


@pytest.mark.asyncio
async def test_model_unavailable_does_not_affect_live_source_or_grant_pass():
    class BrokenModel:
        async def generate(self, prompt, **kwargs):
            raise RuntimeError("no provider")

    result = await assess_service_syntax(
        syntax_projection("server {\n", extension="conf"), model=BrokenModel(),
    )
    assert result["status"] == "llm_review_unavailable"
    assert result["vendor_validated"] is False


def test_llm_never_receives_raw_configuration_in_source_or_candidate():
    src = 'global\nserver "TOP_SECRET_PASSWORD" {\n}\n'
    candidate = src.replace(" {", " ")
    first = syntax_projection(src, extension="conf")
    second = syntax_projection(candidate, extension="conf")
    assert "TOP_SECRET_PASSWORD" not in json.dumps(first)
    assert "TOP_SECRET_PASSWORD" not in json.dumps(second)
    assert "server" in first["lines"][1]["syntax"]
    assert "{" in first["lines"][1]["syntax"]



def test_nginx_verified_vendor_error_yields_candidate_projection_for_second_llm_pass():
    source = b"events {\n}\nserver {{\n}\n"
    preview = local_config_review(
        base64.b64encode(source).decode(), path="/etc/nginx/nginx.conf",
        validator_error_line=3,
        vendor_service="nginx", vendor_error='unexpected "{"',
    )
    assert preview["status"] == "candidate_proposed"
    assert preview["proposed_change"] == "remove_extra_opening_brace"
    assert preview["candidate_syntax_projection"] is not None
    assert preview["validation_status"] == "UNVERIFIED"
    assert preview["apply_eligible"] is False
    unauthorized = local_config_review(
        base64.b64encode(source).decode(), path="/etc/nginx/nginx.conf",
        validator_error_line=3,
        vendor_service="other", vendor_error='unexpected "{"',
    )
    assert unauthorized["candidate_syntax_projection"] is None


@pytest.mark.asyncio
async def test_incident_config_read_does_not_persist_transient_file_projections(monkeypatch):
    from apps.incident_copilot import vm_read
    from apps import config_syntax_llm

    async def fake_review(source, candidate=None, *, model=None, file_type='', vendor_status=''):
        assert sanitized_projection(source) is not None
        return {"status": "reviewed_twice", "model_validated": False,
                "vendor_validated": False, "approval_eligible": False}
    monkeypatch.setattr(config_syntax_llm, "assess_service_syntax", fake_review)

    file_one = "/etc/haproxy/haproxy.cfg"
    file_two = "/opt/app/application.yaml"

    class MCP:
        async def service_config_review(self, target, service):
            return {
                "success": True, "target": target, "service": service,
                "config_file": file_one,
                "syntax_projection": syntax_projection(
                    "frontend foo\n bind *:8080\n", extension="cfg"),
                "file_reviews": [
                    {"path": file_one, "file_type": "cfg",
                     "syntax_projection": syntax_projection(
                         "frontend foo\n bind *:8080\n", extension="cfg")},
                    {"path": file_two, "file_type": "yaml",
                     "syntax_projection": syntax_projection(
                         "server: foo\n", extension="yaml")},
                ],
            }

    observation = await vm_read(
        "service_config_review",
        {"target": "192.0.2.33", "service": "haproxy"}, connector=MCP(),
    )
    assert observation["success"] is True
    assert observation["model_syntax_review"]["model_validated"] is False
    assert len(observation["file_model_reviews"]) == 2
    assert "syntax_projection" not in observation
    assert "candidate_syntax_projection" not in observation
    for entry in observation["file_reviews"]:
        assert "syntax_projection" not in entry
        assert "candidate_syntax_projection" not in entry


@pytest.mark.asyncio
async def test_evidence_collector_triggers_llm_and_discards_grammar(monkeypatch):
    from apps.context_service.evidence_collector import EvidenceCollector
    from apps import config_syntax_llm

    calls = []
    async def fake_assessment(shape, patched=None, **kwargs):
        calls.append((shape, patched, kwargs))
        return {"status": "reviewed_twice", "model_diagnosis": {
            "error_kind": "extra_delimiter", "repair_kind": "remove_token",
            "line": 5, "reason": "review needed",
        }, "vendor_validated": False, "approval_eligible": False}

    monkeypatch.setattr(config_syntax_llm, "assess_service_syntax", fake_assessment)
    source = syntax_projection("server {{\n}\n", extension="conf")
    raw = {
        "success": True, "status": "candidate_proposed",
        "config_file": "/etc/nginx/nginx.conf", "file_type": "conf",
        "syntax_projection": source,
        "candidate_syntax_projection": syntax_projection("server {\n}\n", extension="conf"),
        "file_reviews": [
            {"path": "/etc/nginx/nginx.conf", "syntax_projection": source},
            {"path": "/opt/app/config.yaml", "file_type": "yaml",
             "syntax_projection": syntax_projection("server: config\n", extension="yaml")},
        ],
    }
    safe = await EvidenceCollector._analyze_config_syntax_without_persisting_grammar(raw)
    assert len(calls) == 2
    assert safe["config_llm_review"]["status"] == "reviewed_twice"
    assert len(safe["file_model_reviews"]) == 2
    assert "syntax_projection" not in safe
    assert "candidate_syntax_projection" not in safe
    assert all("syntax_projection" not in row for row in safe["file_reviews"])
    assert safe["config_llm_review"]["vendor_validated"] is False
    assert safe["config_llm_review"]["approval_eligible"] is False
