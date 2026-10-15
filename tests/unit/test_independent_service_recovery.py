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
