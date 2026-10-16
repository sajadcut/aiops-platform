"""Regression for 9cdca567: applied config followed by systemd Running.

The incident initially crashed >850 times. The old status combiner compared
post-repair status against the crash that the successful production write had
already fixed, turning *every* recheck into 'unstable', skipping reconciliation.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.api.incident_chat import _observed_status
from apps.api.config_change_review import _last_config_apply_result
from apps.incident_service.service_recovery_reconciliation import (
    _bound_systemd_observation,
    local_recovery_decision,
)


TARGET = "10.248.16.82"
SERVICE = "gfpapi"
APPROVAL = "60bb5112-c817-4a0f-9f21-cafd87cef497"


def _sample(at, active, sub, count, *, event=False, pid=None):
    raw = {
        "success": True, "target": TARGET, "service": SERVICE,
        "load_state": "loaded", "active_state": active, "sub_state": sub,
        "result": "success", "restart_count": count,
        "main_pid": pid if pid is not None else 0,
    }
    if event:
        return {
            "event_type": "incident_service_status_rechecked",
            "event_id": at, "status": "success", "created_at": at,
            "metadata": {"observation": raw},
        }
    return {
        "source": "vm_mcp", "created_at": at, "reference": at,
        "raw_data": {"diagnostic": "service_status", **raw},
    }


def _applied(at="2026-10-16T16:24:11Z", *, service=SERVICE,
             verified=True, target=TARGET):
    return {
        "event_id": "applied-event",
        "event_type": "configuration_change_transition",
        "status": ("applied_config_vendor_verified" if verified
                   else "config_execution_not_verified"),
        "created_at": at,
        "metadata": {
            "approval_id": APPROVAL, "service": service, "target": target,
            "production_write_performed": verified,
            "rollback_status": "not_required",
            "service_recovery_confirmed": False,
            "service_start_attempted": False,
            "service_recovery_status": "not_authorized",
        },
    }


def test_verified_apply_starts_new_observation_epoch_not_fabricated_health():
    crash = _sample("2026-10-16T16:21:01Z", "activating", "auto-restart", 853)
    first = _sample("2026-10-16T16:24:45Z", "active", "running", 873,
                    event=True, pid=1791923)
    second = _sample("2026-10-16T16:25:02Z", "active", "running", 873,
                     event=True, pid=1791923)

    was_crash = _observed_status(SERVICE, TARGET, [crash], [first, second])
    assert was_crash["status"] == "unstable"
    now_running = _observed_status(
        SERVICE, TARGET, [crash], [_applied(), first, second],
    )
    assert now_running["status"] == "running"
    assert now_running["active_state"] == "active"
    assert now_running["sub_state"] == "running"
    assert now_running["restart_count"] == 873
    assert now_running["main_pid"] == 1791923
    assert now_running["application_health_verified"] is False
    assert "stability_reason" not in now_running


@pytest.mark.parametrize("applied", [
    _applied(service="unrelated"),
    _applied(target="192.0.2.99"),
    _applied(verified=False),
])
def test_unbound_or_failed_change_cannot_erase_existing_crash(applied):
    crash = _sample("2026-10-16T16:21:01Z", "activating", "auto-restart", 853)
    running = _sample("2026-10-16T16:24:45Z", "active", "running", 873, event=True)
    result = _observed_status(SERVICE, TARGET, [crash], [applied, running])
    assert result["status"] == "unstable"


def test_new_post_repair_crash_or_restart_growth_still_flags_instability():
    crash = _sample("2026-10-16T16:21:01Z", "activating", "auto-restart", 853)
    running = _sample("2026-10-16T16:24:45Z", "active", "running", 873, event=True)
    new_crash = _sample("2026-10-16T16:25:15Z", "activating", "auto-restart",
                        874, event=True)
    newest = _sample("2026-10-16T16:25:16Z", "active", "running", 874, event=True)
    result = _observed_status(
        SERVICE, TARGET, [crash], [_applied(), running, new_crash, newest],
    )
    assert result["status"] == "unstable"
    assert result["stability_reason"] == "auto_restart_cycle_observed"


def test_allowlisted_live_status_preserves_safe_numeric_fields():
    obs = {
        "success": True, "target": TARGET, "service": SERVICE,
        "load_state": "loaded", "active_state": "active", "sub_state": "running",
        "restart_count": 873, "main_pid": 1791923,
        "systemctl_status": "may include arbitrary text / secrets",
    }
    result = _bound_systemd_observation(obs, target=TARGET, service=SERVICE)
    assert result["restart_count"] == 873
    assert result["main_pid"] == 1791923
    assert "systemctl_status" not in result


def test_successful_config_apply_audit_separates_file_and_start():
    events = [
        {"event_type": "configuration_change_transition",
         "status": "applied_config_vendor_verified", "created_at": "2026-10-16T16:24:11Z",
         "metadata": {
             "approval_id": "other-approval", "service": SERVICE,
             "production_write_performed": True,
         }},
        _applied(),
    ]
    found = _last_config_apply_result(
        {"approval_id": APPROVAL, "status": "consumed"}, events,
    )
    assert found["config_apply_verified"] is True
    assert found["production_write_performed"] is True
    assert found["service_start_attempted"] is False
    assert found["service_recovery_confirmed"] is False
    assert found["approval_id"] == APPROVAL
    assert _last_config_apply_result(
        {"approval_id": "another"}, events,
    ) is None


def test_systemd_recovery_needs_two_live_checks_but_not_http_health():
    first = {
        "success": True, "target": TARGET, "service": SERVICE,
        "active_state": "active", "sub_state": "running",
    }
    args = {
        "source": "zabbix", "summary": "GFPAPI Systemd Service Down",
        "service": SERVICE, "context": {"related_signals": []},
        "target": TARGET, "vendor_syntax_ok": None,
    }
    assert local_recovery_decision(
        **args, first=first, second={**first},
    ) == "independent_vm_verified"
    assert local_recovery_decision(
        **args, first=first, second=None,
    ) == "second_check_unavailable"
    assert local_recovery_decision(
        **{**args, "context": {"related_signals": [{
            "source": "zabbix", "source_id": "other-signal",
        }]}}, first=first, second={**first},
    ) == "other_correlated_signals"


def test_recheck_includes_prior_apply_audit_and_ui_uses_durable_outcome():
    root = Path(__file__).resolve().parents[2]
    backend = (root / "apps/api/incident_chat.py").read_text()
    ui = (root / "dashboards/incident-command-room.js").read_text()
    assert "history = await PostgreSQLAuditStore(db).list(str(incident_id), 200)" in backend
    assert '"observation": safe_observation if success else None' in backend
    assert "state.configResponse?.last_execution" in ui
    assert "Audited configuration apply result" in ui
    assert "renderOutcome(shown);renderDecision(shown)" in ui
