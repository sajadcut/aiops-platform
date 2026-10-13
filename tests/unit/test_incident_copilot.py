"""Incident room copilot governance and multi-turn read-only interaction contracts."""
from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.incident_copilot import (
    vm_binding, fallback_intent, public_result, vm_read, llm_plan, history,
)
from apps.api.incident_chat import _explicit_wrong_target, _safe_brief
from apps.remediation_planner import RemediationPlanner


def evidence(target="10.248.16.82", service="nginx", diagnostic="service_status",
             success=True, **attrs):
    return {"source": "vm_mcp", "reference": "service-status-1",
            "raw_data": {"diagnostic": diagnostic, "target": target,
                         "service": service, "success": success, **attrs}}


def test_binding_corroborated_with_one_incident_and_never_from_llm():
    rows = [evidence()]
    bound = vm_binding("nginx", rows)
    assert bound["target"] == "10.248.16.82"
    assert bound["service"] == "nginx"
    assert bound["evidence_refs"] == ["service-status-1"]
    assert vm_binding("haproxy", rows) is None
    assert vm_binding("nginx", rows + [evidence(target="10.248.16.83")]) is None
    assert vm_binding("nginx", rows, {"service_identity": {"conflicts": [{"field": "service"}]}}) is None
    assert vm_binding("nginx", rows, {"trigger_signal": {"source": "zabbix",
                     "payload": {"service": "haproxy", "target_ip": "10.248.16.82"}}}) is None
    assert vm_binding("nginx", rows, {"trigger_signal": {"source": "zabbix",
                     "payload": {"service": "nginx", "target_ip": "10.248.16.83"}}}) is None


def test_chat_cannot_redirect_vm_write_to_another_host_or_service():
    bound = vm_binding("nginx", [evidence()])
    assert _explicit_wrong_target("روی 10.248.16.83 ریستارت کن", bound)
    assert _explicit_wrong_target("سرویس haproxy رو ریلود کن", bound)
    assert not _explicit_wrong_target("nginx را از همین سرور بررسی کن", bound)
    assert not _explicit_wrong_target("همین سرویس را reload کن", bound)


@pytest.mark.parametrize("operator, expected", [
    ("ریلود سرویس همین رخداد", "propose_reload"),
    ("restart this service", "propose_restart"),
    ("استارت کن", "propose_start"),
    ("ببین nginx کانفیگ خطا داره", "config_validate"),
    ("لاگ این سرویس را بررسی کن", "service_logs"),
    ("وضعیت همین سرویس چیست؟", "service_status"),
    ("تجربه های مشابه در کاگنیا رو بیار", "knowledge_search"),
    ("علت مشکل چیست؟", "answer"),
])
def test_intent_fallback_without_overriding_host(operator, expected):
    assert fallback_intent(operator) == expected


def test_tool_result_drops_arbitrary_config_and_credentials():
    data = public_result("nginx_config_review", {
        "success": True, "config_file": "/etc/nginx/nginx.conf",
        "error_line": 103, "current_hash": "a" * 64,
        "config_contents": "secret=DO_NOT_LEAK", "raw_config": "DO_NOT_LEAK",
        "environment": {"TOKEN": "DO_NOT_LEAK"},
        "diff": {"line": 103, "before": "[structural] {", "after": "[blank or comment]"},
    })
    assert data["error_line"] == 103
    assert data["current_hash"] == "a"*64
    assert "DO_NOT_LEAK" not in json.dumps(data)


@pytest.mark.asyncio
async def test_vm_read_reuses_only_server_bound_target_and_service():
    calls = []
    class VM:
        async def config_validate(self, target, service):
            calls.append((target, service))
            return {"success": True, "supported": True, "valid": False,
                    "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
                    "target": target, "service": service}
    bound = vm_binding("nginx", [evidence()])
    data = await vm_read("config_validate", bound, connector=VM())
    assert calls == [("10.248.16.82", "nginx")]
    assert data["valid"] is False
    assert data["error_line"] == 103


@pytest.mark.asyncio
async def test_model_can_propose_reload_without_being_given_execute_authority():
    class Model:
        async def generate_with_messages(self, messages, **kwargs):
            assert any("Bounded incident evidence" in msg["content"] for msg in messages)
            return SimpleNamespace(content=json.dumps({
                "intent": "propose_reload",
                "answer": "پیشنهاد می‌کنم بعد از اعتبارسنجی مجدد کانفیگ، درخواست Reload بررسی شود.",
                "target": "10.248.16.99",
                "command": "systemctl reload nginx",
                "approval": True,
            }), finish_reason="stop")
    reply = await llm_plan("این سرویس را ریلود کنیم؟", {"incident_summary": {"service": "nginx"}},
                           [], llm=Model())
    assert reply["intent"] == "propose_reload"
    assert "target" not in reply and "command" not in reply and "approval" not in reply
    assert "پیشنهاد" in reply["answer"]


def _vm_evidence(diagnostic, target="10.248.16.82", service="nginx", **details):
    return {"source": "vm_mcp", "reference": diagnostic, "raw_data": {
        "diagnostic": diagnostic, "target": target, "service": service,
        "success": True, **details,
    }}


def _execution():
    return {"tool_name": "ssh_vm", "runbook_id": "vm-service-recovery",
            "action": "reload_service", "target": "10.248.16.82",
            "parameters": {"service": "nginx"}}


def test_reload_requires_live_active_service_and_real_valid_config():
    status = _vm_evidence("service_status", active_state="active")
    valid = _vm_evidence("config_validate", supported=True, valid=True)
    good = RemediationPlanner.revalidate_execution(_execution(), [status, valid])
    assert good["safe_to_execute"] is True
    assert good["action"] == "reload_service"
    invalid = _vm_evidence("config_validate", supported=True, valid=False)
    assert RemediationPlanner.revalidate_execution(_execution(), [status, invalid])["reason"] == "service_configuration_invalid"
    missing = RemediationPlanner.revalidate_execution(_execution(), [status])
    assert missing["safe_to_execute"] is False
    failed = _vm_evidence("service_status", active_state="failed")
    outcome = RemediationPlanner.revalidate_execution(_execution(), [failed, valid])
    assert outcome["safe_to_execute"] is False
    assert outcome["reason"] == "reload_requires_healthy_active_service"
    unknown = _vm_evidence("config_validate", supported=False, valid=None)
    assert not RemediationPlanner.revalidate_execution(_execution(), [status, unknown])["safe_to_execute"]


def test_existing_recovery_not_weakened_for_non_reload_actions():
    requested = {**_execution(), "action": "restart_service"}
    state = _vm_evidence("service_status", active_state="active")
    validator = _vm_evidence("config_validate", supported=True, valid=True)
    assert RemediationPlanner.revalidate_execution(requested, [state, validator])["safe_to_execute"] is False


def test_history_is_limited_to_matching_audit_events_and_role():
    events = [
        {"event_type": "incident_copilot_turn", "event_id": "assistant-1",
         "created_at": "2026-10-13T21:00:00+03:30",
         "metadata": {"role": "assistant", "message": "تحلیل", "kind": "answer"}},
        {"event_type": "incident_copilot_read", "metadata": {"role": "assistant", "message": "read"}},
        {"event_type": "incident_copilot_turn", "event_id": "user-1",
         "created_at": "2026-10-13T20:59:00+03:30",
         "metadata": {"role": "user", "message": "چرا خطا؟", "kind": "user"}},
    ]
    assert [(x["role"], x["message"]) for x in history(events)] == [
        ("user", "چرا خطا؟"), ("assistant", "تحلیل")
    ]


def test_incident_chat_routes_have_auth_and_deployable_dashboard():
    from apps.api.main import app
    with TestClient(app) as client:
        incident = "00000000-0000-4000-8000-000000000001"
        get = client.get("/api/v1/incidents/"+incident+"/chat")
        post = client.post("/api/v1/incidents/"+incident+"/chat", json={"message": "status"})
        approval = client.post("/api/v1/incidents/"+incident+"/chat/request-approval",
                               json={"proposal_id": incident})
    assert get.status_code in {401, 403}
    assert post.status_code in {401, 403}
    assert approval.status_code in {401, 403}
    html = Path("dashboards/incident-command-room.html").read_text(encoding="utf-8")
    js = Path("dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert 'href="#ic-chat"' in html
    assert 'id="ic-chat-form"' in html
    assert "request-approval" in js
    assert "ic-chat-thread" in js


def test_safe_brief_excludes_untrusted_raw_evidence_and_secret_fields():
    output = _safe_brief({
        "incident_summary": {"service": "nginx", "summary": "nginx failure",
                             "secret_key": "private-value"},
        "raw_evidence": {"config": "private-value"},
        "agents": [{"agent": "vm", "findings": ["syntax error"]}],
    })
    assert "private-value" not in json.dumps(output)
    assert output["incident_summary"]["service"] == "nginx"
