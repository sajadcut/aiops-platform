"""Cognia review must show sourced config fault and real recovery state."""
from uuid import uuid4

from apps.knowledge_review_dossier import (
    build_dossier, dossier_addendum, dossier_title,
)
from apps.incident_followup import knowledge_candidate
from apps.knowledge_review import incident_document


INCIDENT = str(uuid4())
REF = str(uuid4())


def _diagnostic():
    return {
        "id": REF, "source": "vm_mcp",
        "raw_data": {
            "service": "nginx", "target": "192.0.2.10",
            "diagnostic": "config_validate", "success": True,
            "supported": True, "valid": False,
            "config_file": "/etc/nginx/nginx.conf",
            "error_line": 103,
            "syntax_error": 'unexpected "{" in /etc/nginx/nginx.conf:103',
        },
    }


def _apply(confirmed=False):
    return {
        "event_type": "configuration_change_transition",
        "status": "applied_config_vendor_verified",
        "event_id": str(uuid4()),
        "metadata": {
            "approval_id": "example-approval",
            "production_write_performed": True,
            "service_recovery_confirmed": confirmed,
            "service_start_attempted": confirmed,
        },
    }


def _dossier(*, evidence=None, audits=None, status="open", recovery=None):
    return build_dossier(
        incident_id=INCIDENT, service="nginx", incident_status=status,
        evidence=evidence if evidence is not None else [_diagnostic()],
        audits=audits if audits is not None else [_apply()],
        source_recovery=recovery,
    )


def test_config_fault_and_vendor_verified_apply_are_distinct_from_recovery():
    dossier = _dossier()
    assert dossier["config_diagnostic"]["config_file"] == "/etc/nginx/nginx.conf"
    assert dossier["config_diagnostic"]["error_line"] == 103
    assert dossier["config_diagnostic"]["error_kind"] == "unexpected_opening_brace"
    assert dossier["config_execution"]["config_apply"] == "vendor_verified"
    assert dossier["monitor_recovered"] is False
    text = dossier_addendum(dossier)
    assert "/etc/nginx/nginx.conf" in text
    assert "103" in text and "آکولاد باز" in text
    assert "هنوز معادل" not in text  # no false systemd success
    assert "فعال‌شدن سرویس پس از اصلاح در این رکورد تأیید نشده" in text
    assert "تأیید نشده" in text
    assert "خطای کانفیگ" in dossier_title("nginx", dossier)


def test_source_recovery_requires_real_zabbix_marker_and_resolved_incident():
    marker = {"source": "zabbix", "incident_resolved": True}
    assert _dossier(status="open", recovery=marker)["monitor_recovered"] is False
    assert _dossier(status="resolved", recovery=marker)["monitor_recovered"] is True
    assert _dossier(status="resolved", recovery={"source": "manual", "incident_resolved": True})[
        "monitor_recovered"] is False
    assert _dossier(audits=[_apply(True)])["monitor_recovered"] is False


def test_unrelated_service_and_untrusted_content_never_enter_dossier():
    other = _diagnostic()
    other["raw_data"] = dict(other["raw_data"], service="mysql", error_line=777)
    bad = _diagnostic()
    bad["raw_data"] = dict(
        bad["raw_data"], config_file="/etc/nginx/private password=secret.conf",
        error_line=44, syntax_error="password=secret",
    )
    d = _dossier(evidence=[other, bad], audits=[])
    assert d["config_diagnostic"] is None
    text = dossier_addendum(d)
    assert not text
    assert "password" not in str(d)


def test_vendor_success_only_does_not_invent_a_prior_fault():
    good = _diagnostic()
    good["raw_data"] = dict(good["raw_data"], valid=True)
    d = _dossier(evidence=[good], audits=[_apply()])
    assert d["config_diagnostic"] is None
    assert dossier_addendum(d) == ""


def test_followup_draft_includes_actual_config_details_without_claiming_recovery():
    dossier = _dossier()
    title, content = knowledge_candidate(
        incident_id=uuid4(), service="nginx", evidence_ref=REF,
        diagnostic="service_status", state={"context": {"evidence": []}},
        dossier=dossier,
    )
    assert "/etc/nginx/nginx.conf:103" in title
    assert "آکولاد باز غیرمنتظره" in content
    assert "اعمال فایل: با موفقیت" in content
    assert "تأیید نشده" in content
    assert "نه دستورات اجرایی" in content


def test_no_unverified_source_is_upgraded_to_a_config_root_cause():
    d = _dossier()
    assert "Root cause:" not in dossier_addendum(d)
    assert "Cause confirmed" not in dossier_addendum(d)
