"""The intelligence report MUST answer the received alert, even without LLM."""
from datetime import datetime, timezone
from pathlib import Path

from apps.decision_brief import build_decision_brief
from apps.incident_alert_focused_report import build_alert_focused_report
from apps.decision_brief_narrative import projection

NOW = datetime(2026, 10, 19, 17, 0, tzinfo=timezone.utc)


def _record(eid, source, raw, created="2026-10-19T16:59:00Z"):
    return {
        "id": eid, "source": source, "created_at": created,
        "raw_data": raw,
    }


def _brief(evidence, summary="GFP API Redis errors reached 10 events in the last 2 minutes"):
    return build_decision_brief(
        incident={
            "id": "incident-redis", "service": "gfpapi", "severity": "high",
            "status": "analyzing", "summary": summary,
            "context": {"source": "zabbix"},
        },
        operator_summary={"likely_cause": "unverified", "cause_confidence": "unknown"},
        checkpoint={"state": {}, "version": 1},
        durable_evidence=evidence,
        findings=[], audit_events=[],
        now=NOW,
    )


def test_redis_alarm_is_primary_even_when_unrelated_systemd_is_active():
    message = "GFP API Redis errors reached 10 events in the last 2 minutes"
    evidence = [
        _record("vm-unit", "vm_mcp", {
            "mcp_server": "vm_mcp", "tool_name": "service_status",
            "success": True, "service": "gfpapi", "target": "10.248.16.82",
            "active_state": "active", "unit_id": "gfpapi.service",
        }),
        _record("vm-redis", "vm_mcp", {
            "mcp_server": "vm_mcp", "tool_name": "dependency_investigation",
            "success": True,
            "checks_executed": 1,
            "dependencies": [{
                "kind": "redis", "host": "cache.internal", "port": 6379,
                "probe_status": "tcp_reachable", "tcp_reachable": True,
                "protocol_status": "client_not_installed",
                "config_key": "Redis.Endpoints.Host",
                "password": "TOP_SECRET_DO_NOT_PRINT",
            }],
        }),
        _record("trigger", "zabbix", {
            "signal_type": message, "signal_summary": message,
            "name": message, "service": "gfpapi", "event_value": "1",
        }),
    ]
    brief = _brief(evidence)
    alert = brief["alert_focused_report"]
    assert alert["alert_message"] == message
    assert alert["source_basis"] == "received_signal"
    assert alert["alert_source"] == "Zabbix"
    assert alert["alert_evidence_ref"] == "trigger"
    assert alert["family"] == "redis"
    assert alert["status"] == "related_checks_recorded"
    assert [x["tool"] for x in alert["related_checks"]] == ["dependency_investigation"]
    assert alert["related_checks"][0]["evidence_ref"] == "vm-redis"
    assert "TCP برقرار" in alert["related_checks"][0]["result"]
    assert "client_not_installed" in alert["related_checks"][0]["result"]
    assert "TOP_SECRET_DO_NOT_PRINT" not in str(brief)
    assert alert["root_cause_confirmed"] is False
    assert alert["authorizes_execution"] is False
    assert "Redis" in str(projection(brief)["received_alert_focus"])


def test_database_alert_does_not_use_unrelated_redis_probe_as_proof():
    signal = "PostgreSQL connection timeout at checkout service"
    evidence = [
        _record("trigger", "prometheus", {
            "signal_type": "postgres_connection_timeout",
            "signal_summary": signal,
            "annotations": {"summary": signal},
        }),
        _record("redis", "vm_mcp", {
            "mcp_server": "vm_mcp", "tool_name": "dependency_investigation",
            "success": True, "dependencies": [{
                "kind": "redis", "host": "redis.local", "port": 6379,
                "tcp_reachable": True, "protocol_status": "unauthenticated_ping_ok",
            }],
        }),
    ]
    report = _brief(evidence, signal)["alert_focused_report"]
    assert report["family"] == "database"
    assert report["source_basis"] == "received_signal"
    assert report["status"] == "no_relevant_checks"
    assert report["related_checks"] == []
    assert "تست فنی مستقل" in report["assessment_fa"]


def test_http_alert_uses_http_endpoint_check_not_systemd_state():
    message = "HTTPS upstream API returned 503"
    report = _brief([
        _record("original", "elasticsearch", {
            "signal_type": "http_5xx", "signal_summary": message,
            "name": message,
        }),
        _record("downstream", "vm_mcp", {
            "mcp_server": "vm_mcp", "tool_name": "dependency_investigation",
            "success": True, "dependencies": [{
                "kind": "https", "host": "upstream.internal", "port": 8443,
                "http_status": 503, "probe_status": "http_responded",
            }],
        }),
    ], message)["alert_focused_report"]
    assert report["family"] == "http"
    assert report["status"] == "related_checks_recorded"
    assert "upstream.internal" in report["related_checks"][0]["result"]


def test_original_problem_is_preserved_when_recovery_notification_arrives():
    original = "ActiveMQ broker queue depth exceeded threshold"
    report = _brief([
        _record("recovery", "zabbix", {
            "signal_type": "activemq_recovered", "signal_summary": "Queue recovered",
            "name": "Queue recovered", "zabbix_lifecycle_state": "recovery",
        }, "2026-10-19T17:02:00Z"),
        _record("initial", "zabbix", {
            "signal_type": "activemq_queue", "signal_summary": original,
            "name": original,
        }, "2026-10-19T16:59:00Z"),
    ], original)["alert_focused_report"]
    assert report["alert_message"] == original
    assert report["alert_evidence_ref"] == "initial"
    assert report["family"] == "messaging"


def test_another_services_redis_evidence_cannot_verify_this_incident():
    message = "Redis timeout on order-api"
    evidence = [
        _record("trigger", "zabbix", {
            "signal_type": "Redis timeout", "signal_summary": message,
            "name": message, "service": "order-api",
        }),
        _record("wrong-service", "vm_mcp", {
            "mcp_server": "vm_mcp", "tool_name": "dependency_investigation",
            "success": True, "service": "billing-api",
            "dependencies": [{
                "kind": "redis", "host": "cache.internal", "port": 6379,
                "probe_status": "tcp_reachable", "tcp_reachable": True,
            }],
        }),
    ]
    brief = build_decision_brief(
        incident={"id": "other-service", "service": "order-api",
                  "summary": message, "status": "analyzing", "context": {}},
        operator_summary={}, checkpoint={"state": {}, "version": 1},
        durable_evidence=evidence, findings=[], audit_events=[], now=NOW,
    )
    report = brief["alert_focused_report"]
    assert report["status"] == "no_relevant_checks"
    assert report["related_checks"] == []


def test_custom_dependency_is_supported_by_keyword_grounded_check():
    message = "Hazelcast cluster partition timeout"
    evidence = [
        _record("original", "zabbix", {
            "signal_type": "cluster_alert", "signal_summary": message,
            "name": message,
        }),
        _record("diagnostic", "vm_mcp", {
            "mcp_server": "vm_mcp", "tool_name": "dependency_investigation",
            "success": True, "checks_executed": 1,
            "dependencies": [{
                "kind": "hazelcast", "host": "hazelcast.internal", "port": 5701,
                "probe_status": "tcp_unreachable", "tcp_reachable": False,
            }],
        }),
    ]
    report = _brief(evidence, message)["alert_focused_report"]
    assert report["family"] == "other"
    assert report["status"] == "related_checks_recorded"
    assert report["related_checks"][0]["evidence_ref"] == "diagnostic"
    assert report["root_cause_confirmed"] is False


def test_incident_without_ingress_still_has_honest_alert_focused_answer():
    summary = "Unusual Python worker latency spike"
    report = _brief([], summary)["alert_focused_report"]
    assert report["alert_message"] == summary
    assert report["source_basis"] == "incident_summary_fallback"
    assert report["alert_evidence_ref"] == ""
    assert report["status"] == "no_relevant_checks"
    assert report["read_only"] is True


def test_intelligence_report_has_mandatory_alert_section_before_systemd():
    js = Path("dashboards/incident-command-room.js").read_text(encoding="utf-8")
    begin = js.index("function renderIntelligenceReport(r)")
    section = js[begin:js.index("function renderTechnicalInvestigation(r)", begin)]
    assert "data-alert-focus" in section
    assert "alert_focused_report" in section
    assert "alert.alert_message" in section
    assert "alert.assessment_fa" in section
    assert "alert.next_check_fa" in section
    assert section.index("section(fa?'۱. آلارم") < section.index("section(fa?'۲. وضعیت مکمل")
