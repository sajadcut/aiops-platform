"""Safe Nginx preview runs on the AIOps worker, without target Python/writes."""
import base64
import hashlib
import json

import pytest

from integrations.vm.nginx_config_review import nginx_review_command, local_nginx_review
from integrations.vm.service_adapters import parse_config_diagnostic
from integrations.vm.ssh_connector import SSHVMConnector
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner


ERROR = (
    '2026/10/13 17:49:43 [warn] 12#12: user directive ignored in /etc/nginx/nginx.conf:43\n'
    '2026/10/13 17:49:43 [emerg] 12#12: unexpected "{" in /etc/nginx/nginx.conf:103\n'
    'nginx: configuration file /etc/nginx/nginx.conf test failed'
)
_CONFIG = (
    "events { worker_connections 1024; }\n"
    + "# non-sensitive\n" * 101
    + "server example.internal {{\n"
    + "password=DO_NOT_LEAK\n"
)
_LINE = 103
_ENCODED = base64.b64encode(_CONFIG.encode()).decode()


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


def test_nginx_preview_uses_only_remote_read_only_coreutils():
    cmd = nginx_review_command("/etc/nginx/nginx.conf", 103, ERROR)
    assert "/etc/nginx/nginx.conf" in cmd
    for expected in ("readlink -f", "stat -c", "head -c", "base64 -w 0", "test ! -L"):
        assert expected in cmd
    for forbidden in ("python3", "python -", "sed -i", "cp ", "mv ", "tee ", "nginx -s", "sudo ", "chmod ", "chown "):
        assert forbidden not in cmd
    assert "user directive ignored" not in cmd


def test_nginx_local_worker_creates_bounded_redacted_candidate_without_staging():
    result = local_nginx_review(
        encoded=_ENCODED, file_path="/etc/nginx/nginx.conf",
        error_line=_LINE, syntax_error='unexpected "{"',
    )
    assert result["status"] == "candidate_proposed"
    assert result["validation_status"] == "UNVERIFIED"
    assert result["stage_failure_reason"] == "isolated_validation_not_available"
    assert result["validator_executed_on_proposal"] is False
    assert result["remote_python_required"] is False
    assert result["execution_authority"] is False
    assert result["config_contents_exposed"] is False
    assert result["current_hash"] == hashlib.sha256(_CONFIG.encode()).hexdigest()
    assert result["candidate_hash"] != result["current_hash"]
    assert result["diff"]["line"] == 103
    assert "server" in result["diff"]["before"]
    assert "{" in result["diff"]["after"]
    for secret in ("DO_NOT_LEAK", "example.internal", "1024"):
        assert secret not in json.dumps(result)


@pytest.mark.parametrize("encoded,line,error", [
    ("not-base64#", 103, 'unexpected "{"'),
    (base64.b64encode(b"x" * 262145).decode(), 103, 'unexpected "{"'),
    (_ENCODED, 999, 'unexpected "{"'),
    (_ENCODED, 103, 'unknown directive "server"'),
    (base64.b64encode(b"server {\r\n").decode(), 1, 'unexpected "{"'),
    (base64.b64encode(b"server {\x00").decode(), 1, 'unexpected "{"'),
])
def test_nginx_preview_fails_closed_on_invalid_input_and_nonmatching_error(encoded,line,error):
    result = local_nginx_review(
        encoded=encoded, file_path="/etc/nginx/nginx.conf",
        error_line=line, syntax_error=error,
    )
    assert result["status"] != "candidate_proposed"
    assert not result["candidate_hash"]
    assert not result["execution_authority"]


@pytest.mark.asyncio
async def test_mcp_review_uses_worker_preview_and_never_exports_encoded_configuration(monkeypatch):
    connector = SSHVMConnector()
    calls = []
    async def validate(target, service):
        return {
            "success": True, "supported": True, "valid": False,
            "config_file": "/etc/nginx/nginx.conf", "error_line": _LINE,
            "syntax_error": 'unexpected "{"',
        }
    async def run(target, command):
        calls.append((target, command))
        return {"success": True, "stdout": _ENCODED}
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "_run", run)
    outcome = await connector.nginx_config_review("10.248.16.82", "nginx")
    assert len(calls) == 1
    assert "python" not in calls[0][1]
    assert outcome["config_file"] == "/etc/nginx/nginx.conf"
    assert outcome["error_line"] == 103
    assert outcome["candidate_hash"]
    assert outcome["validation_status"] == "UNVERIFIED"
    assert outcome["stage_failure_reason"] == "isolated_validation_not_available"
    assert outcome["execution_authority"] is False
    assert outcome["remote_python_required"] is False
    assert outcome["config_contents_exposed"] is False
    for secret in ("DO_NOT_LEAK", "example.internal", _ENCODED):
        assert secret not in json.dumps(outcome)


@pytest.mark.asyncio
async def test_worker_preview_unavailable_if_remote_file_cannot_be_read(monkeypatch):
    connector = SSHVMConnector()
    async def validate(target, service):
        return {
            "success": True, "supported": True, "valid": False,
            "config_file": "/etc/nginx/nginx.conf", "error_line": _LINE,
            "syntax_error": 'unexpected "{"',
        }
    async def run(target, command):
        return {"success": False, "stderr": "PRIVATE:DO_NOT_LEAK"}
    monkeypatch.setattr(connector, "_validate_service", lambda _: None)
    monkeypatch.setattr(connector, "config_validate", validate)
    monkeypatch.setattr(connector, "_run", run)
    outcome = await connector.nginx_config_review("10.248.16.82", "nginx")
    assert outcome["status"] == "preview_unavailable"
    assert outcome["config_file"] == "/etc/nginx/nginx.conf"
    assert outcome["error_line"] == 103
    assert outcome["remote_python_required"] is False
    assert outcome["execution_authority"] is False
    assert "DO_NOT_LEAK" not in json.dumps(outcome)


@pytest.mark.asyncio
async def test_dynamic_investigator_uses_bounded_worker_candidate_not_approval():
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
             **local_nginx_review(
                 encoded=_ENCODED, file_path="/etc/nginx/nginx.conf",
                 error_line=103, syntax_error='unexpected "{"',
             )}
    }
    state={"service_name":"nginx","coordination":{"missing_evidence":[]},
           "knowledge_results":[],"context":{"evidence":[error,review]}}
    proposal=await DynamicInvestigationPlanner.propose(state, adapter=Model())
    candidate=proposal["config_proposal"]
    assert candidate["error_line"] == 103
    assert candidate["validation_status"]=="UNVERIFIED"
    assert candidate["apply_eligible"] is False
    assert candidate["execution_authority"] is False
    assert candidate["original_sha256"] and candidate["candidate_sha256"]
    assert candidate["redacted_diff"]["line"]==103
    assert proposal["operator_questions"]


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
    assert 'data-config-intent="request_change_approval"' in js
    assert 'href="#ic-ai-proposed-fix"' in js
    assert 'اعمال اصلاح روی سرور — غیرفعال' not in js
    assert 'پس از مشاهده Diff، درخواست تغییر را به صف Approval بفرستید' in js
    assert 'ارسال درخواست به Approval' in js
    assert 'state.configResponseStatus===\'loaded\'' in js
    assert 'state.historic' in js
    assert 'config.candidate_sha256' in js and 'config.original_sha256' in js
    # The UI submits only the existing read-only review response, never a
    # fabricated patch or a config-file execution request.
    assert "base+'/configuration-review-response'" in js
    assert 'data-config-intent="apply"' not in js
    assert 'data-config-request-status="recorded"' in js


@pytest.mark.asyncio
async def test_confirmed_nginx_validator_collects_preview_without_dynamic_llm_flag(monkeypatch):
    from datetime import datetime, timezone
    from apps.context_service.evidence_collector import EvidenceCollector
    from integrations.vm.target_context import bind_vm_target, reset_vm_target
    from domain.contracts.config import settings

    monkeypatch.setattr(settings, "AIOPS_DYNAMIC_INVESTIGATION_ENABLED", False)
    actions = []

    class VM:
        async def config_validate(self, target, service):
            actions.append("config_validate")
            return {
                "success": True, "supported": True, "valid": False,
                "service": service, "config_file": "/etc/nginx/nginx.conf",
                "error_line": 103, "syntax_error": 'unexpected "{"',
            }
        async def nginx_config_review(self, target, service):
            actions.append("nginx_config_review")
            return {
                "success": True, "supported": True, "service": service,
                "status": "candidate_proposed",
                "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
                "current_hash": "a"*64, "candidate_hash": "b"*64,
                "validation_status": "UNVERIFIED",
                "remote_python_required": False,
                "execution_authority": False,
            }
        async def nginx_config_inspect(self, target, service):
            actions.append("nginx_config_inspect")
            return {"success": True, "service": service, "status": "inspected",
                    "files": [], "config_contents_exposed": False}
    token = bind_vm_target("10.248.16.82")
    try:
        context = await EvidenceCollector(vm=VM()).collect_requested(
            "nginx", datetime.now(timezone.utc),
            [{"evidence_type": "telemetry", "reason": "configuration syntax validation",
              "preferred_source": "vm"}],
        )
    finally:
        reset_vm_target(token)
    assert actions == ["config_validate", "nginx_config_review", "nginx_config_inspect"]
    stored = [
        row.get("raw_data", {}) for row in (context.get("evidence") or [])
        if row.get("source") == "vm_mcp"
    ]
    assert any(row.get("diagnostic") == "nginx_config_review"
               and row.get("status") == "candidate_proposed"
               for row in stored)
    assert all(row.get("execution_authority") is not True for row in stored)


def test_existing_nginx_incident_can_request_read_only_preview_from_dashboard():
    from pathlib import Path
    from apps.incident_copilot import fallback_intent
    js = (Path(__file__).resolve().parents[2] /
          "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert fallback_intent(
        "nginx_config_review: برای این رخداد فقط پیش‌نمایش امن اصلاح Nginx را بساز"
    ) == "nginx_config_review"
    assert 'data-config-preview="' in js
    assert "service==='nginx'?'nginx':verified.length?'review':'generic'" in js
    assert "nginx_config_review: فقط پیش‌نمایش" in js
    assert "service_config_discovery: مسیر فایل‌های تنظیمات" in js
    assert "اعمال اصلاح روی سرور — غیرفعال" not in js
    assert "ارسال درخواست به Approval" in js



@pytest.mark.asyncio
async def test_dynamic_nginx_config_preview_survives_llm_opt_out():
    validator = {
        "source": "vm_mcp", "reference": "failed-validator",
        "raw_data": {
            "diagnostic": "config_validate", "success": True,
            "supported": True, "valid": False, "service": "nginx",
            "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
            "syntax_error": 'unexpected "{"',
        },
    }
    reviewed = {
        "source": "vm_mcp", "reference": "safe-preview",
        "raw_data": {
            "diagnostic": "nginx_config_review", "success": True,
            "service": "nginx", "config_file": "/etc/nginx/nginx.conf",
            "error_line": 103, **local_nginx_review(
                encoded=_ENCODED, file_path="/etc/nginx/nginx.conf",
                error_line=103, syntax_error='unexpected "{"',
            ),
        },
    }
    state = {
        "service_name": "nginx", "coordination": {"missing_evidence": []},
        "knowledge_results": [], "context": {"evidence": [validator, reviewed]},
    }
    proposal = await DynamicInvestigationPlanner.propose(state, adapter=None)
    assert proposal["model_status"] == "skipped_deterministic_read_only"
    assert proposal["config_proposal"]["status"] == "candidate_proposed"
    assert proposal["config_proposal"]["validator_executed_on_proposal"] is False
    assert proposal["config_proposal"]["apply_eligible"] is False
    assert proposal["config_proposal"]["original_sha256"]
    assert proposal["config_proposal"]["candidate_sha256"]
