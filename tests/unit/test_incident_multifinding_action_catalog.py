"""Multi-finding incidents must show every action path without fabricating authority."""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.incident_remediation_opportunities import build_remediation_opportunities
from apps.api.config_change_review import (
    _last_config_apply_result,
    _consumed_failure_reissuable,
)
from integrations.vm.governed_config_change import classify_config_guard_failure


INCIDENT = {"service": "gfpapi", "summary": "GFPAPI Systemd Service Down"}
HOST = "192.0.2.27"


def _record(tool, payload, time="2026-10-16T17:16:00+00:00"):
    return {
        "source": "vm_mcp",
        "created_at": time,
        "raw_data": {
            "success": True, "diagnostic": tool, "target": HOST,
            **payload,
        },
    }


def _report(invalid=True):
    return {
        "incident_summary": {"target": HOST, "service": "gfpapi"},
        "configuration_diagnostic": {
            "status": "invalid" if invalid else "valid",
            "config_file": "/opt/example/appsettings.json",
        },
        "approval_readiness": {"approval_id": "config-ticket"},
        "dynamic_investigation": {
            "config_proposal": {"status": "candidate_proposed"}
        },
    }


def test_one_incident_three_independent_action_paths():
    evidence = [
        _record("service_status", {
            "service": "gfpapi", "active_state": "activating",
            "sub_state": "auto-restart",
        }),
        _record("disk_status", {
            "filesystems": [
                {"mount": "/", "use_percent": "9%"},
                {"mount": "/var/log", "use_percent": "100%", "available": "20480"},
            ],
        }),
    ]
    actions = build_remediation_opportunities(
        incident=INCIDENT, evidence=evidence, report=_report(),
    )
    assert {entry["id"] for entry in actions} == {
        "configuration_syntax", "systemd_recovery", "filesystem_pressure:/var/log",
    }
    assert all(entry["execution_authorized"] is False for entry in actions)
    assert actions[0]["action"] == "config_review"
    assert actions[1]["status"] == "independent_approval_required"
    assert actions[2]["action"] == "disk_investigation"
    assert actions[2]["status"] == "executor_unavailable"
    assert "logrotate" in actions[2]["remediation_fa"]
    assert "حذف" in actions[2]["blocker_fa"]


def test_no_disk_action_for_other_vm_or_healthy_mount():
    evidence = [
        _record("disk_status", {
            "target": "192.0.2.29",
            "filesystems": [{"mount": "/var/log", "use_percent": "100%"}],
        }),
        _record("disk_status", {
            "filesystems": [{"mount": "/var/log", "use_percent": "24%"}],
        }),
    ]
    actions = build_remediation_opportunities(
        incident=INCIDENT, evidence=evidence, report=_report(invalid=False),
    )
    assert actions == []


def test_service_already_running_does_not_offer_restart_from_historical_alarm():
    actions = build_remediation_opportunities(
        incident=INCIDENT,
        evidence=[_record("service_status", {
            "service": "gfpapi", "active_state": "active", "sub_state": "running",
        })],
        report=_report(invalid=False),
    )
    assert not any(x["action"] == "service_recheck" for x in actions)


def test_interrupted_config_apply_preserves_unknown_and_no_replay():
    approval = {"approval_id": "a9"}
    event = {
        "event_type": "configuration_change_transition",
        "status": "config_execution_not_verified",
        "metadata": {
            "approval_id": "a9", "result": "config_apply_result_unknown",
            "failure_reason": "config_guard_ssh_stdin_closed_result_unknown",
            "production_write_performed": None,
            "service": "gfpapi",
        },
    }
    result = _last_config_apply_result(approval, [event])
    assert result["production_write_performed"] is None
    assert result["failure_reason"] == "config_guard_ssh_stdin_closed_result_unknown"
    assert _consumed_failure_reissuable(approval, [event]) is False
    assert classify_config_guard_failure(
        {"success": False, "error": "ssh_stdin_pipe_closed"}
    ) == "config_guard_ssh_stdin_closed_result_unknown"


def test_multifinding_ui_has_real_navigation_and_no_fake_disk_apply():
    root = Path(__file__).resolve().parents[2]
    page = (root / "dashboards/incident-command-room.html").read_text()
    js = (root / "dashboards/incident-command-room.js").read_text()
    assert 'id="ic-remediation-actions"' in page
    assert "renderRemediationActions(r)" in js
    assert "data-incident-chat-prompt=\"disk\"" in js
    assert 'action===\'disk_investigation\'' in js
    assert "guardReasonFA(applied.failure_reason)" in js
