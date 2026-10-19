"""Incident room uses the same bounded diagnostic chain with audit-safe projection."""
import pytest
from apps.incident_copilot import fallback_intent, _bounded_investigation_report


def test_incident_causal_question_selects_governed_investigation():
    assert fallback_intent("چرا سرویس gfpapi بالا نمیاد؟") == "vm_investigate"
    assert fallback_intent("مشکل سرویس را اصلاح کن") != "vm_investigate"


def test_incident_projection_hides_raw_journal_lines_and_config_text():
    report = {
        "success": True, "target": "vm1", "service": "gfpapi",
        "scope": "service_start_failure", "partial": False,
        "observations": [
            {"tool": "service_logs", "why": "logs", "status": "observed",
             "data": {"success": True, "logs": [
                 "secret password=not_for_audit",
                 "syntax error at config line 10",
             ]}},
            {"tool": "service_status", "status": "observed",
             "data": {"success": True, "target": "vm1", "service": "gfpapi",
                      "active_state": "failed", "raw_sensitive": "credentials"}},
        ],
    }
    report = _bounded_investigation_report(report)
    from json import dumps
    data = dumps(report)
    assert "secret password" not in data
    assert "credentials" not in data
    assert "syntax error" in data
    assert report["observations"][1]["data"]["active_state"] == "failed"
