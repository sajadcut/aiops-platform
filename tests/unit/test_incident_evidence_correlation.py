"""Operational truth: alerts and systemd observations are not the same thing."""
from datetime import datetime, timedelta, timezone

import pytest

from apps.incident_evidence_correlation import correlate_incident_state
from apps.decision_brief import build_decision_brief
from apps.incident_explanation import explain_incident

NOW = datetime(2026, 10, 14, 14, 2, tzinfo=timezone.utc)


def incident(*, host="10.248.16.82", original_time=None):
    original = {"message": "GFPAPI Systemd Service Down",
                "service": "gfpapi", "target_ip": host}
    if original_time:
        original["timestamp"] = original_time
    return {
        "id": "incident-01", "service": "gfpapi", "status": "analyzing",
        "summary": "GFPAPI Systemd Service Down",
        "context": {"trigger_signal": {
            "source": "zabbix", "summary": "GFPAPI Systemd Service Down",
            "timestamp": "2026-10-14T14:00:00+00:00",
            "raw_data": {"service": "gfpapi", "target_ip": host,
                         "_received_payload": original},
        }},
    }


def vm(status="active", *, at="2026-10-14T14:01:00+00:00",
       host="10.248.16.82", service="gfpapi", ref="vm-001"):
    return {"id": ref, "source": "vm_mcp", "created_at": at,
            "raw_data": {"diagnostic": "service_status", "success": True,
                         "collected_at": at, "service": service, "target": host,
                         "active_state": status,
                         "sub_state": "running" if status == "active" else "failed",
                         "main_pid": 442 if status == "active" else 0}}


def correlate(*, incident_data=None, evidence=None, events=None, checkpoint=None):
    return correlate_incident_state(
        incident=incident_data or incident(), checkpoint=checkpoint or {"state": {}},
        evidence=evidence if evidence is not None else [vm()],
        audit_events=events or [], now=NOW,
    )


def test_alert_down_vm_running_no_source_timestamp_produces_explicit_discrepancy():
    c = correlate()
    assert c["conclusion_kind"] == "source_discrepancy"
    assert "اختلاف وضعیت شناسایی شد" in c["headline_fa"]
    assert "Zabbix" in c["headline_fa"] and "Running" in c["headline_fa"]
    assert c["alert"]["observed_at"] is None
    assert c["alert"]["received_at"] == "2026-10-14T14:00:00+00:00"
    assert c["contradictions"][0]["temporal_relation"] == "undetermined"
    assert c["root_cause_verified"] is False
    assert c["confirmed_vm_transition"] is None
    assert "زمان وقوع دقیق" in " ".join(c["unknowns_fa"])
    assert not any(h["status"] == "confirmed" for h in c["hypotheses"])
    assert c["authorizes_execution"] is False


def test_explicit_zabbix_event_before_vm_does_not_prove_real_recovery():
    c = correlate(incident_data=incident(original_time="2026-10-14T14:00:08Z"))
    assert c["contradictions"][0]["temporal_relation"] == "alert_event_before_vm_observation"
    assert c["alert"]["time_basis"] == "source_event"
    assert c["confirmed_vm_transition"] is None
    assert c["hypotheses"][0]["status"] == "unverified"
    assert "بازیابی شده" in " ".join(c["unknowns_fa"])


def test_vm_observation_before_alert_is_not_wrongly_reported_as_recovery():
    c = correlate(incident_data=incident(original_time="2026-10-14T14:01:45Z"))
    assert c["contradictions"][0]["temporal_relation"] == "vm_observation_before_alert_event"
    assert c["confirmed_vm_transition"] is None


def test_same_timestamp_is_not_proof_of_order():
    c = correlate(incident_data=incident(original_time="2026-10-14T14:01:00Z"))
    assert c["contradictions"][0]["temporal_relation"] == "same_timestamp_no_order"


def test_direct_vm_stopped_then_running_confirms_only_observed_transition():
    c = correlate(evidence=[
        vm("failed", at="2026-10-14T14:00:30+00:00", ref="vm-failed"),
        vm("active", at="2026-10-14T14:01:00+00:00", ref="vm-active"),
    ])
    assert c["confirmed_vm_transition"]["kind"] == "direct_vm_state_transition"
    assert c["confirmed_vm_transition"]["from"]["evidence_refs"] == ["vm-failed"]
    assert c["confirmed_vm_transition"]["to"]["evidence_refs"] == ["vm-active"]
    assert c["root_cause_verified"] is False


def test_mismatched_host_is_never_used_as_direct_telemetry():
    c = correlate(evidence=[vm(host="10.248.16.83")])
    assert c["conclusion_kind"] == "insufficient_direct_evidence"
    assert c["last_vm_observation"] is None
    assert not c["contradictions"]


def test_multi_host_without_declared_target_is_not_combined():
    x = incident()
    x["context"]["trigger_signal"]["raw_data"].pop("target_ip")
    x["context"]["trigger_signal"]["raw_data"]["_received_payload"].pop("target_ip")
    c = correlate(incident_data=x, evidence=[vm(host="10.248.16.82"),vm(host="10.248.16.83")])
    assert c["last_vm_observation"] is None
    assert not c["contradictions"]
    assert "چند میزبان متفاوت" in " ".join(c["unknowns_fa"])


def test_agent_or_non_vm_claim_cannot_become_direct_running_evidence():
    c = correlate(evidence=[{
        **vm(), "source": "zabbix"
    }])
    assert c["last_vm_observation"] is None
    assert c["root_cause_verified"] is False


def test_running_systemd_with_unhealthy_http_is_its_own_contradiction():
    event = {"event_type": "service_http_health_rechecked", "event_id": "audit-http",
             "created_at": "2026-10-14T14:01:30Z",
             "metadata": {"service": "gfpapi", "target": "10.248.16.82",
                          "status": "unhealthy", "http_code": 503}}
    c = correlate(events=[event])
    types = {x["contradiction_type"] for x in c["contradictions"]}
    assert "zabbix_down_vs_vm_systemd_running" in types
    assert "systemd_running_but_http_unhealthy" in types
    assert c["http_observation"]["status"] == "unhealthy"
    assert c["hypotheses"][2]["status"] == "supported_not_confirmed"
    assert c["authorizes_execution"] is False


def test_http_audit_other_host_does_not_claim_api_healthy():
    event = {"event_type": "service_http_health_rechecked", "event_id": "other-http",
             "created_at": "2026-10-14T14:01:30Z",
             "metadata": {"service": "gfpapi", "target": "10.248.16.91",
                          "status": "healthy"}}
    assert correlate(events=[event])["http_observation"] is None


def test_process_name_false_is_not_proof_dotnet_is_stopped():
    process = {"id": "ps-1", "source": "vm_mcp",
               "created_at": "2026-10-14T14:01:30Z",
               "raw_data": {"diagnostic": "process_status", "success": True,
                            "service": "gfpapi", "target": "10.248.16.82",
                            "running": False, "count": 0}}
    c = correlate(evidence=[vm(), process])
    assert "MainPID" in " ".join(c["unknowns_fa"])
    explanation = explain_incident(
        evidence=[vm(), process], service="gfpapi", correlation=c)
    assert "اختلاف وضعیت شناسایی شد" in explanation["headline_fa"]
    assert not any("فرایند مورد بررسی" in x["text_fa"]
                   for x in explanation["confirmed_findings"])


def test_no_vm_status_does_not_claim_shutdown_from_zabbix_alone():
    c = correlate(evidence=[])
    assert c["headline_fa"] is None
    assert c["confirmed_vm_transition"] is None


def test_old_timeout_cannot_override_new_running_discrepancy():
    earlier = vm("failed", at="2026-10-13T14:00:00+00:00", ref="old-timeout")
    earlier["raw_data"]["result"] = "timeout"
    c = correlate(evidence=[earlier,vm()])
    exp = explain_incident(evidence=[earlier, vm()], service="gfpapi", correlation=c)
    assert exp["headline_fa"].startswith("اختلاف وضعیت شناسایی شد")
    assert not any("توقف سرویس gfpapi تأیید شد" in x["text_fa"]
                   for x in exp["confirmed_findings"])


def test_monitoring_recovery_audit_does_not_imply_aiops_restarted_service():
    audit = [{"event_id":"recovery","event_type":"verification_source_recovery_received",
              "actor":"zabbix_webhook", "created_at":"2026-10-14T14:01:40Z"}]
    c = correlate(events=audit)
    assert c["confirmed_vm_transition"] is None
    assert c["authorizes_execution"] is False


def test_decision_brief_exposes_real_sources_and_prioritized_conclusion():
    summary={"observed_state":{"target":"10.248.16.82"},"likely_cause":None}
    brief=build_decision_brief(
        incident=incident(),
        checkpoint={"state":{"evaluation":{"confidence":0.71,"decision":"blocked"}},"version":9},
        operator_summary=summary,durable_evidence=[vm()],findings=[],audit_events=[],
        now=NOW,
    )
    assert brief["state_correlation"]["conclusion_kind"]=="source_discrepancy"
    assert brief["state_correlation"]["host"]=="10.248.16.82"
    assert "Zabbix" in brief["operator_explanation"]["headline_fa"]
    assert "Running" in brief["operator_explanation"]["headline_fa"]
    assert brief["source_policy"]["authorizes_execution"] is False
    assert brief["state_correlation"]["root_cause_verified"] is False
    assert brief["state_correlation"]["contradictions"][0]["source_b"]["source"]=="vm_mcp"


def test_generic_config_unsupported_does_not_drown_out_source_discrepancy():
    config={"id":"unsupported","source":"vm_mcp","created_at":"2026-10-14T14:01:05Z",
            "raw_data":{"diagnostic":"config_validate","service":"gfpapi",
                        "target":"10.248.16.82","success":True,"supported":False}}
    brief=build_decision_brief(
        incident=incident(),operator_summary={},
        checkpoint={"state":{}}, durable_evidence=[vm(),config],findings=[],
        audit_events=[],now=NOW,
    )
    exp=brief["operator_explanation"]
    assert "اختلاف وضعیت شناسایی شد" in exp["headline_fa"]
    assert "روش عمومی اعتبارسنجی" in " ".join(exp["uncertainties_fa"])
    assert "زمان" in " ".join(exp["next_steps_fa"])



def test_minute_only_event_time_must_not_claim_temporal_order():
    c = correlate(incident_data=incident(original_time="2026-10-14T14:00Z"))
    assert c["alert"]["time_basis"] == "source_event_minute_only"
    assert c["contradictions"][0]["temporal_relation"] == "undetermined"


def test_normalized_zabbix_timestamp_is_not_original_occurrence():
    x = incident()
    trigger = x["context"]["trigger_signal"]
    trigger["raw_data"].pop("_received_payload")
    trigger["raw_data"]["timestamp"] = "2026-10-14T14:00:08Z"
    c = correlate(incident_data=x)
    assert c["alert"]["observed_at"] is None
    assert c["alert"]["received_at"] == "2026-10-14T14:00:00+00:00"


def test_observation_other_service_on_same_host_cannot_validate_trigger():
    c = correlate(evidence=[vm(service="nginx")])
    assert c["last_vm_observation"] is None
    assert c["confirmed_vm_transition"] is None



def test_one_undated_vm_observation_can_conflict_without_claiming_chronology():
    source = vm()
    source["created_at"] = None
    source["raw_data"].pop("collected_at")
    c = correlate(evidence=[source])
    assert c["conclusion_kind"] == "source_discrepancy"
    assert c["last_vm_observation"]["observed_at"] is None
    assert c["contradictions"][0]["temporal_relation"] == "undetermined"
    assert "فاقد Timestamp" in " ".join(c["unknowns_fa"])


def test_active_exited_systemd_is_not_conflated_with_running_service():
    x = vm()
    x["raw_data"]["sub_state"] = "exited"
    c = correlate(evidence=[x])
    assert c["last_vm_observation"] is None
    assert not c["contradictions"]



def test_zabbix_recovery_is_not_aiops_restart_and_does_not_close_open_incident():
    a = {"event_type": "verification_source_recovery_received",
         "event_id": "zabbix-recovery-01", "actor": "zabbix_webhook",
         "created_at": "2026-10-14T14:02:00Z"}
    c = correlate(events=[a])
    assert any(x.get("source") == "zabbix" and
               "نه اجرای اصلاح توسط AIOps" in x["text_fa"]
               for x in c["confirmed_observations"])
    assert c["root_cause_verified"] is False
    assert c["confirmed_vm_transition"] is None
    assert c["authorizes_execution"] is False
    assert "Closure" in " ".join(c["unknowns_fa"])


def test_failed_systemd_vs_named_process_running_requests_pid_cgroup_check():
    row={"source":"vm_mcp","id":"proc-present",
         "created_at":"2026-10-14T14:01:02Z",
         "raw_data":{"diagnostic":"process_status", "success":True,
                     "service":"gfpapi", "target":"10.248.16.82",
                     "running":True, "count":1}}
    c=correlate(evidence=[vm("failed"),row])
    matching=[x for x in c["contradictions"]
              if x["contradiction_type"]=="systemd_failed_vs_named_process_running"]
    assert len(matching)==1
    assert matching[0]["interpretation"]=="process_ownership_and_time_not_verified"
    assert matching[0]["evidence_refs"]==["vm-001","proc-present"]
    assert "MainPID" in " ".join(c["next_steps_fa"])
    assert c["root_cause_verified"] is False


def test_json_syntax_valid_does_not_overrule_failed_service_or_prove_dependencies():
    config={"id":"dotnet-valid","source":"vm_mcp","created_at":"2026-10-14T14:01:20Z",
            "raw_data":{"diagnostic":"dotnet_config_syntax","success":True,
                        "service":"gfpapi","target":"10.248.16.82",
                        "syntax_valid":True,
                        "files":[{"file":"appsettings.json","status":"valid_json_syntax"}]}}
    c=correlate(evidence=[vm("failed"),config])
    assert "Syntax JSON معتبر" in " ".join(c["unknowns_fa"])
    assert "Startup" in " ".join(c["next_steps_fa"])
    assert c["root_cause_verified"] is False



def elastic_query(status="queried", count=0, *,
                  service="gfpapi", ref="elastic-q-01"):
    return {"id": ref, "source": "elasticsearch",
            "created_at": "2026-10-14T14:01:20Z",
            "raw_data": {"service": service, "query_service": service,
                         "status": status, "result_count": count,
                         "query_since": "2026-10-14T13:45:00Z",
                         "query_until": "2026-10-14T14:02:00Z",
                         "host_filter_applied": False}}


def vm_journal(host="10.248.16.82", *, service="gfpapi",
               entries=None, ref="journal-01"):
    return {"id": ref, "source": "vm_mcp",
            "created_at": "2026-10-14T14:01:30Z",
            "raw_data": {"diagnostic": "service_logs", "target": host,
                         "service": service, "entries": entries or []}}


def test_elastic_zero_and_os_errors_are_scope_mismatch_not_healthy_or_root_cause():
    check = correlate(evidence=[
        vm(), elastic_query(), vm_journal(entries=[
            "dotnet ERROR database failed", "startup timed out",
            "kernel: OOM-kill process", "dependency failed to start",
        ])])["cross_source_findings"][0]
    assert check["kind"] == "elastic_vs_host_journal_coverage"
    assert check["status"] == "scope_mismatch_not_a_contradiction"
    assert check["journal_signatures"] == {
        "error": 2, "timeout": 1, "oom": 1, "dependency": 1,
    }
    assert "Elasticsearch برای سرویس نتیجهٔ صفر" in check["statement_fa"]
    assert "Journal همین VM" in check["statement_fa"]
    assert "نبود خطای OS نیست" in check["statement_fa"]
    assert "جست‌وجوی Elastic به میزبان مشخص محدود نشده" in check["statement_fa"]
    assert set(check["evidence_refs"]) == {"elastic-q-01", "journal-01"}
    assert not check["cause_confirmed"]


def test_failed_elastic_query_is_not_zero_hits_even_with_os_journal():
    check = correlate(evidence=[
        vm(), elastic_query("error"), vm_journal(entries=["Application exception"]),
    ])["cross_source_findings"][0]
    assert check["status"] == "query_failed_not_zero"
    assert "تعداد Match نامعلوم" in check["statement_fa"]
    assert "نتیجهٔ صفر ثبت کرده" not in check["statement_fa"]


def test_elastic_matches_do_not_prove_host_scope_or_cause():
    check = correlate(evidence=[
        vm(), elastic_query("queried", 5),
    ])["cross_source_findings"][0]
    assert check["status"] == "elastic_results_not_host_causality"
    assert check["query_scope"] == "service_only_or_host_filter_unverified"
    assert "تعداد 5 رکورد" in check["statement_fa"]
    assert check["cause_confirmed"] is False


def test_provider_scope_does_not_combine_other_services_or_other_host_journal():
    checks = correlate(evidence=[
        vm(),
        elastic_query(service="nginx", ref="wrong-service"),
        vm_journal(host="10.248.16.83", entries=["ERROR nginx"], ref="wrong-host"),
    ])["cross_source_findings"]
    assert checks == []


def test_database_persisted_timestamp_is_not_vm_tool_observed_time():
    src=vm()
    src["raw_data"].pop("collected_at")
    result=correlate(incident_data=incident(original_time="2026-10-14T14:00:00Z"),
                     evidence=[src])
    assert result["last_vm_observation"]["time_basis"] == "evidence_persisted"
    assert result["contradictions"][0]["temporal_relation"] == "undetermined"
    assert "زمان ثبت Evidence" in " ".join(result["unknowns_fa"])


def test_database_persisted_timestamp_cannot_confirm_vm_state_transition():
    stop=vm("failed", at="2026-10-14T14:00:30Z", ref="vm-stopped")
    up=vm("active", at="2026-10-14T14:01:00Z", ref="vm-active")
    stop["raw_data"].pop("collected_at")
    up["raw_data"].pop("collected_at")
    assert correlate(evidence=[stop,up])["confirmed_vm_transition"] is None


def test_provider_journal_comparison_is_not_triggered_by_unscoped_logs():
    unscoped={"id":"unscoped-journal","source":"vm_mcp",
              "raw_data":{"diagnostic":"service_logs","service":"gfpapi",
                          "entries":["ERROR unrelated"]}}
    c=correlate(evidence=[vm(),elastic_query(),unscoped])
    check=c["cross_source_findings"][0]
    assert check["journal_signatures"]["error"] == 0
    assert check["status"]=="queried_zero_not_proof_of_health"
