"""Contract regression: nginx fatal location and strictly non-executing previews."""
import json
import re

import pytest

from integrations.vm.nginx_config_review import nginx_review_command
from integrations.vm.service_adapters import parse_config_diagnostic
from integrations.vm.ssh_connector import SSHVMConnector
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner


ERROR = (
    '2026/10/13 17:49:43 [warn] 12#12: user directive ignored in /etc/nginx/nginx.conf:43\n'
    '2026/10/13 17:49:43 [emerg] 12#12: unexpected "{" in /etc/nginx/nginx.conf:103\n'
    'nginx: configuration file /etc/nginx/nginx.conf test failed'
)


def test_nginx_fatal_location_overrides_earlier_warning():
    result = parse_config_diagnostic(ERROR)
    assert result["config_file"] == "/etc/nginx/nginx.conf"
    assert result["error_line"] == 103
    assert 'unexpected "{"' in result["syntax_error"]


@pytest.mark.parametrize("path,line", [
    ("/tmp/nginx.conf", 103),
    ("/etc/passwd", 103),
    ("/etc/nginx/../passwd", 103),
    ("/etc/nginx/nginx.conf;rm -rf /", 103),
    ("/etc/nginx/nginx.conf", 0),
    ("/etc/nginx/nginx.conf", True),
])
def test_nginx_preview_never_accepts_untrusted_remote_path_or_line(path,line):
    with pytest.raises(ValueError):
        nginx_review_command(path, line, 'unexpected "{"')


def test_preview_command_only_contains_immutable_script_and_derived_line():
    cmd = nginx_review_command("/etc/nginx/nginx.conf", 103, ERROR)
    assert "python3 -I -c " in cmd
    assert "unexpected_open_brace" in cmd
    assert "nginx_config_review" not in cmd
    assert "/etc/nginx/nginx.conf" in cmd


@pytest.mark.asyncio
async def test_preview_is_built_from_current_validator_and_redacts_remote_values(monkeypatch):
    connector = SSHVMConnector()
    # No mock of network or credential: explicitly monkeypatch the fixed read.
    calls = []
    async def validate(target, service):
        return {
            "success": True, "supported": True, "valid": False,
            "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
            "syntax_error": 'unexpected "{" in /etc/nginx/nginx.conf:103',
        }
    async def run(target, command):
        calls.append((target, command))
        return {"success": True, "stdout": json.dumps({
            "status": "candidate_proposed", "validation_status": "STAGED_PASS_NOT_ISOLATED",
            "current_hash": "a" * 64, "candidate_hash": "b" * 64,
            "current_excerpt": [{"line": 103, "content": "[structural] {"}],
            "proposed_excerpt": [{"line": 103, "content": "[blank or comment]"}],
            "diff": {"line": 103, "before": "[structural] {",
                     "after": "[remove entire stray brace line]"},
            "validator_executed_on_proposal": True,
            "proposed_change": "remove_extra_opening_brace",
            "test_scope": "staged_copy_with_live_dependencies_not_isolated",
            "config_contents": "DO_NOT_LEAK",
            "secret": "DO_NOT_LEAK",
        })}
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "_run", run)
    outcome = await connector.nginx_config_review("10.248.16.82", "nginx")
    assert len(calls) == 1
    assert outcome["config_file"] == "/etc/nginx/nginx.conf"
    assert outcome["error_line"] == 103
    assert outcome["candidate_hash"] == "b"*64
    assert outcome["validation_status"] == "STAGED_PASS_NOT_ISOLATED"
    assert outcome["execution_authority"] is False
    assert outcome["config_contents_exposed"] is False
    assert "DO_NOT_LEAK" not in json.dumps(outcome)


@pytest.mark.asyncio
async def test_review_never_claims_validated_when_staging_fails(monkeypatch):
    connector = SSHVMConnector()
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    async def validate(target,service):
        return {"success": True, "supported": True, "valid": False,
                "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
                "syntax_error": 'unexpected "{"'}
    async def run(target,command):
        return {"success": True,"stdout":json.dumps({
            "status":"candidate_proposed", "current_hash":"a"*64,
            "candidate_hash":"b"*64, "validation_status":"STAGED_FAILED",
            "validator_executed_on_proposal":True,
        })}
    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "_run", run)
    outcome=await connector.nginx_config_review("10.248.16.82","nginx")
    assert outcome["validation_status"]=="STAGED_FAILED"
    assert not outcome.get("apply_eligible",False)
    assert outcome["execution_authority"] is False


@pytest.mark.asyncio
async def test_dynamic_investigator_proposal_preserves_nonisolated_status_without_approval():
    from types import SimpleNamespace
    class Model:
        async def generate_with_messages(self, *args, **kwargs):
            return SimpleNamespace(content='{"checks":[],"question":""}',finish_reason="stop")
    error = {
        "source":"vm_mcp", "reference":"validator-103",
        "raw_data":{"diagnostic":"config_validate","success":True,
            "supported":True,"valid":False,"service":"nginx",
            "config_file":"/etc/nginx/nginx.conf","error_line":103,
            "syntax_error":'unexpected "{"'}
    }
    review = {
        "source":"vm_mcp","reference":"review-103",
        "raw_data":{"diagnostic":"nginx_config_review","success":True,"service":"nginx",
             "config_file":"/etc/nginx/nginx.conf", "error_line":103,
             "status":"candidate_proposed","validation_status":"STAGED_PASS_NOT_ISOLATED",
             "current_hash":"a"*64,"candidate_hash":"b"*64,
             "validator_executed_on_proposal":True,
             "current_excerpt":[{"line":103,"content":"[structural] {"}],
             "proposed_excerpt":[{"line":103,"content":"[blank or comment]"}],
             "diff":{"line":103,"before":"[structural] {","after":"[remove entire stray brace line]"}}
    }
    state={"service_name":"nginx","coordination":{"missing_evidence":[]},
           "knowledge_results":[],"context":{"evidence":[error,review]}}
    proposal=await DynamicInvestigationPlanner.propose(state, adapter=Model())
    candidate=proposal["config_proposal"]
    assert candidate["error_line"] == 103
    assert candidate["validation_status"]=="STAGED_PASS_NOT_ISOLATED"
    assert candidate["apply_eligible"] is False
    assert candidate["execution_authority"] is False
    assert candidate["original_sha256"]=="a"*64
    assert candidate["candidate_sha256"]=="b"*64
    assert candidate["redacted_diff"]["line"]==103
    assert proposal["operator_questions"]



def test_nginx_stage_runner_classifies_failure_without_returning_stderr():
    import ast
    from integrations.vm.nginx_config_review import _FIXED_CHECK
    ast.parse(_FIXED_CHECK)
    assert "stderr=subprocess.PIPE" in _FIXED_CHECK
    assert "stage_failure_class(check.stderr or b\"\")" in _FIXED_CHECK
    assert "result[\"stage_failure_reason\"]" in _FIXED_CHECK
    # The return object contains a fixed classifier rather than captured
    # nginx output, which may contain server names and private paths.
    assert 'result["stderr"]' not in _FIXED_CHECK
    assert 'result["stage_error_text"]' not in _FIXED_CHECK


@pytest.mark.asyncio
async def test_nginx_mcp_stage_failure_classification_is_strictly_allowlisted(monkeypatch):
    connector = SSHVMConnector()
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    async def validate(target, service):
        return {"success": True, "supported": True, "valid": False,
                "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
                "syntax_error": 'unexpected "{" in /etc/nginx/nginx.conf:103'}
    async def run(target, command):
        return {"success": True, "stdout": json.dumps({
            "status": "candidate_proposed", "current_hash": "a"*64,
            "candidate_hash": "b"*64, "validation_status": "STAGED_FAILED",
            "stage_failure_reason": "directive_context_invalid",
            "raw_secret": "NEVER_SHOW",
            "validator_executed_on_proposal": True,
        })}
    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "_run", run)
    response = await connector.nginx_config_review("10.248.16.82", "nginx")
    assert response["stage_failure_reason"] == "directive_context_invalid"
    assert response["execution_authority"] is False
    assert "NEVER_SHOW" not in json.dumps(response)

    async def inject_unknown(target, command):
        return {"success": True, "stdout": json.dumps({
            "status": "candidate_proposed", "validation_status": "STAGED_FAILED",
            "stage_failure_reason": "user token=secret-value",
        })}
    monkeypatch.setattr(connector, "_run", inject_unknown)
    unknown = await connector.nginx_config_review("10.248.16.82", "nginx")
    assert unknown["stage_failure_reason"] == "not_recorded"
    assert "secret-value" not in json.dumps(unknown)


@pytest.mark.asyncio
async def test_failed_nginx_candidate_reaches_report_but_never_becomes_approval():
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from apps.decision_brief import build_decision_brief

    class Model:
        async def generate_with_messages(self, *args, **kwargs):
            return SimpleNamespace(content='{"checks":[],"question":""}', finish_reason="stop")

    rows = [
        {"id": "validator-103", "source": "vm_mcp",
         "created_at": "2026-10-14T16:45:32+00:00",
         "raw_data": {
             "diagnostic": "config_validate", "service": "nginx",
             "success": True, "supported": True, "valid": False,
             "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
             "syntax_error": 'unexpected "{" in /etc/nginx/nginx.conf:103',
         }},
        {"id": "review-103", "source": "vm_mcp",
         "created_at": "2026-10-14T16:45:39+00:00",
         "raw_data": {
             "diagnostic": "nginx_config_review", "service": "nginx",
             "success": True, "status": "candidate_proposed",
             "validation_status": "STAGED_FAILED",
             "stage_failure_reason": "directive_context_invalid",
             "current_hash": "a"*64, "candidate_hash": "b"*64,
             "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
             "diff": {"line": 103, "before": "server [arguments redacted] {{",
                      "after": "server [arguments redacted] {"},
             "proposed_change": "remove_extra_opening_brace",
             "validator_executed_on_proposal": True,
         }},
    ]
    state = {"service_name": "nginx", "coordination": {"missing_evidence": []},
             "knowledge_results": [], "context": {"evidence": rows}}
    investigation = await DynamicInvestigationPlanner.propose(state, adapter=Model())
    proposal = investigation["config_proposal"]
    assert proposal["status"] == "candidate_proposed"
    assert proposal["validation_status"] == "STAGED_FAILED"
    assert proposal["stage_failure_reason"] == "directive_context_invalid"
    assert proposal["apply_eligible"] is False
    report = build_decision_brief(
        incident={"id": "incident-nginx-103", "service": "nginx", "status": "analyzing"},
        operator_summary={}, checkpoint={"state": {
            "context": {"dynamic_investigation": investigation}}},
        durable_evidence=rows, findings=[], audit_events=[],
        now=datetime(2026, 10, 14, 16, 46, tzinfo=timezone.utc),
    )
    output = report["dynamic_investigation"]["config_proposal"]
    assert output["config_file"] == "/etc/nginx/nginx.conf"
    assert output["error_line"] == 103
    assert output["validation_status"] == "STAGED_FAILED"
    assert output["stage_failure_reason"] == "directive_context_invalid"
    assert output["redacted_diff"]["line"] == 103
    assert output["apply_eligible"] is False
    assert output["execution_authority"] is False
    assert report["source_policy"]["authorizes_execution"] is False


def test_nginx_stage_blocker_is_prominent_in_operator_diagnosis_script():
    from pathlib import Path
    browser = (Path(__file__).resolve().parents[2] /
               "dashboards/incident-command-room.js").read_text()
    assert "function nginxCandidateReadiness(r)" in browser
    assert "nginxCandidateReadiness(r)" in browser
    assert "STAGED_FAILED" in browser or "staged_failed" in browser
    assert "مرحله فقط Preview است" in browser
    assert "stage_failure_reason" in browser
    assert "source_evidence_refs" in browser



def test_nginx_repair_entrypoint_is_visible_near_incident_and_never_applies_unvalidated_patch():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    html = (root / "dashboards/incident-command-room.html").read_text(encoding="utf-8")
    js = (root / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    css = (root / "dashboards/incident-command-room.css").read_text(encoding="utf-8")
    assert html.index('id="ic-config-action-banner"') < html.index('id="ic-quick-facts"')
    assert 'href="#ic-ai-proposed-fix" data-i18n="navFix"' in html
    assert 'function renderConfigActionBanner(r)' in js
    assert 'renderConfigActionBanner(r);renderOverview(r)' in js
    assert 'ic-config-banner-actions' in css
    assert 'permission_denied' in js
    assert 'data-config-intent="request_isolated_validation"' in js
    assert 'href="#ic-ai-proposed-fix"' in js
    assert 'اعمال اصلاح روی سرور — غیرفعال' in js
    assert 'ثبت درخواست اعتبارسنجی خودش فایل را اصلاح نمی‌کند' in js
    assert 'state.configResponseStatus===\'loaded\'' in js
    assert 'state.historic' in js
    assert 'config.candidate_sha256' in js and 'config.original_sha256' in js
    # The UI submits only the existing read-only review response, never a
    # fabricated patch or a config-file execution request.
    assert "base+'/configuration-review-response'" in js
    assert 'data-config-intent="apply"' not in js
