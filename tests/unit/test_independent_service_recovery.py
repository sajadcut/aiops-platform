"""Independent service-recovery decisions never forge monitor recovery."""
import pytest

from apps.incident_service.service_recovery_reconciliation import (
    is_service_down_alert, local_recovery_decision,
)


TARGET = "192.0.2.18"
SERVICE = "nginx"
FIRST = {"success": True, "service": SERVICE, "target": TARGET,
         "active_state": "active", "sub_state": "running"}
SECOND = dict(FIRST)


def _decision(**overrides):
    fields = {
        "source": "zabbix", "summary": "nginx Service Down",
        "service": SERVICE, "context": {"related_signals": []},
        "first": FIRST, "second": SECOND, "target": TARGET,
        "vendor_syntax_ok": True,
    }
    fields.update(overrides)
    return local_recovery_decision(**fields)


def test_two_vm_observations_and_vendor_pass_can_confirm_service_down_recovery():
    assert is_service_down_alert("zabbix", "nginx Service Down", "nginx")
    assert _decision() == "independent_vm_verified"


@pytest.mark.parametrize("field,value,expected", [
    ("source", "elastic", "alert_condition_unverified"),
    ("summary", "nginx port 80 unreachable", "alert_condition_unverified"),
    ("summary", "apache Service Down", "alert_condition_unverified"),
    ("second", None, "second_check_unavailable"),
    ("second", {**SECOND, "target": "192.0.2.99"}, "service_not_stably_running"),
    ("second", {**SECOND, "active_state": "failed"}, "service_not_stably_running"),
    ("first", {**FIRST, "sub_state": "exited"}, "service_not_stably_running"),
    ("vendor_syntax_ok", False, "nginx_live_config_not_verified"),
    ("context", {"related_signals": [{"source": "elastic"}]}, "other_correlated_signals"),
    ("context", {"related_signals": [{"source": "zabbix", "source_id": "other-trigger"}]},
     "other_correlated_signals"),
    ("context", {"related_signals": [None]}, "correlation_unverified"),
    ("context", {"related_signals": [17]}, "correlation_unverified"),
    ("context", {"related_signals": [{"source": "zabbix"}, {"source": "zabbix"}]}, "other_correlated_signals"),
    ("context", {"source_recovery": {"incident_resolved": True}}, "source_already_recovered"),
])
def test_unverifiable_recovery_keeps_incident_open(field, value, expected):
    assert _decision(**{field: value}) == expected


def test_unfamiliar_service_can_be_verified_only_for_its_own_explicit_down_alert():
    first = {**FIRST, "service": "my-java-app"}
    second = dict(first)
    assert _decision(service="my-java-app", summary="my-java-app Service Down",
                     first=first, second=second, vendor_syntax_ok=None) == "independent_vm_verified"


def test_no_stale_unrelated_service_or_monitor_condition_can_trigger_auto_resolution():
    assert not is_service_down_alert("zabbix", "nginx high CPU", "nginx")
    assert not is_service_down_alert("zabbix", "nginx Service Down", "apache")
    assert not is_service_down_alert("elastic", "nginx Service Down", "nginx")


@pytest.mark.asyncio
async def test_independent_recovery_atomic_commit_records_audit_and_cancels_approvals():
    from types import SimpleNamespace
    from apps.incident_service.service_recovery_reconciliation import (
        commit_independent_recovery,
    )
    from domain.models import IncidentStatus

    class Result:
        def scalars(self):
            return self
        def all(self):
            return ["pending-approval-id"]

    class Database:
        def __init__(self):
            self.queries = []
            self.flush_count = 0
            self.commit_count = 0
        async def flush(self):
            self.flush_count += 1
        async def execute(self, sql, params):
            self.queries.append((str(sql), params))
            return Result()
        async def commit(self):
            self.commit_count += 1

    incident = SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        service="nginx",
        status=IncidentStatus.ANALYZING,
        context={"related_signals": []},
    )
    db = Database()
    await commit_independent_recovery(
        db, incident=incident, target=TARGET,
        actor="test-operator", recovery_source="vm_mcp_systemd_recheck",
        vendor_syntax_ok=True,
    )
    assert incident.status == IncidentStatus.RESOLVED
    assert incident.context["independent_recovery"]["monitor_recovered"] is False
    assert db.flush_count == 1 and db.commit_count == 1
    assert len(db.queries) == 2
    assert "UPDATE approvals" in db.queries[0][0]
    assert "INSERT INTO audit_events" in db.queries[1][0]
    assert db.queries[1][1]["status"] == "verified"
    assert '"cancelled_approval_count": 1' in db.queries[1][1]["metadata"]


@pytest.mark.asyncio
async def test_unsupported_recovery_source_cannot_mark_incident_resolved():
    from types import SimpleNamespace
    from domain.models import IncidentStatus
    from apps.incident_service.service_recovery_reconciliation import (
        commit_independent_recovery,
    )
    incident = SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        service="nginx", status=IncidentStatus.ANALYZING, context={},
    )
    with pytest.raises(ValueError, match="untrusted_recovery_source"):
        await commit_independent_recovery(
            None, incident=incident, target=TARGET, actor="test",
            recovery_source="model_claimed_recovered", vendor_syntax_ok=True,
        )
    assert incident.status == IncidentStatus.ANALYZING


def test_only_the_original_exact_zabbix_problem_can_be_duplicate_related_signal():
    context = {
        "trigger_signal": {"source_id": "zbx-problem-1"},
        "related_signals": [{"source": "zabbix", "source_id": "zbx-problem-1"}],
    }
    assert _decision(context=context) == "independent_vm_verified"
    context["related_signals"].append({"source": "zabbix", "source_id": "another-problem"})
    assert _decision(context=context) == "other_correlated_signals"


def test_malformed_second_service_status_never_raises_or_resolves():
    assert _decision(second={**SECOND, "service": None}) == "service_not_stably_running"
    assert _decision(second={**SECOND, "service": ["nginx"]}) == "service_not_stably_running"
