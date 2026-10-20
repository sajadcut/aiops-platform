"""Alert text is mandatory first-class triage input, not decoration.

Tests never prove a downstream service failure merely from the alert title.
"""
import pytest

from apps.alert_text_intent import analyze_alert_text, received_alert_intents
from apps.incident_alert_focused_report import build_alert_focused_report
from agents.shared.coordinator import IncidentCoordinator
from agents.triage import TriageAgent


@pytest.mark.parametrize("name,expected_family,condition,route", [
    ("GFP_Backend database connection errors reached at least 10 events in the last 2 minutes",
     "database", "error_threshold", "database"),
    ("GFP_Backend Redis errors reached at least 10 events in the last 2 minutes",
     "redis", "error_threshold", "dependency"),
    ("GFP_Backend PostgreSQL connection refused", "database", "connection_refused", "database"),
    ("GFP_Backend SQL Server connection timeout", "database", "connection_timeout", "database"),
    ("GFP_Backend MongoDB authentication failed", "database", "authentication_error", "database"),
    ("GFP_Backend database connection pool exhausted", "database", "pool_exhaustion", "database"),
    ("GFP_Backend Kafka consumer lag errors", "messaging", "error_reported", "messaging"),
    ("GFP_Backend ActiveMQ broker errors", "messaging", "error_reported", "messaging"),
    ("GFP_Backend RabbitMQ connection refused", "messaging", "connection_refused", "messaging"),
    ("GFP_Backend HTTP upstream 503 errors", "http", "error_reported", "dependency"),
    ("GFP_Backend CPU above threshold", "cpu", "unspecified", "infrastructure"),
])
def test_alert_title_first_without_any_dependency_tags(name,expected_family,condition,route):
    result=analyze_alert_text(name)
    assert result["family"] == expected_family
    assert result["condition"] == condition
    assert result["route"] == route
    assert result["basis"] == "alert_text"
    assert result["root_cause_confirmed"] is False
    alert={"source":"zabbix","type":"alert","raw_data":{
        "name":name, "service":"GFP_Backend",
    }}
    assert TriageAgent._declared_dependency_routes([alert],"GFP_Backend")==[route]


def test_text_wins_over_conflicting_redis_tag_and_conflict_is_reported():
    title="GFP_Backend database connection errors reached at least 10 events in the last 2 minutes"
    parsed=analyze_alert_text(title,dependency_tag="redis")
    assert parsed["family"]=="database"
    assert parsed["condition"]=="error_threshold"
    assert parsed["tag_conflict"] is True
    assert parsed["tag_family"]=="redis"
    evidence=[{"source":"zabbix","type":"alert","reference":"event-100",
        "raw_data":{"payload":{"name":title,"service":"GFP_Backend",
                "tags":[{"tag":"dependency","value":"redis"}]}}}]
    intents=received_alert_intents(evidence,"GFP_Backend")
    assert intents[0]["route"]=="database"
    assert intents[0]["basis"]=="alert_text"
    assert intents[0]["tag_conflict"] is True
    assert intents[0]["evidence_ref"]=="event-100"


def test_tag_is_only_fallback_when_title_does_not_name_technology():
    parsed=analyze_alert_text("GFP_Backend connection errors reached 10",dependency_tag="postgresql")
    assert parsed["family"]=="database"
    assert parsed["basis"]=="tag_fallback"
    assert parsed["condition"]=="error_threshold"


def test_ambiguous_or_negative_text_cannot_be_overridden_to_claim_db_failure():
    mixed=analyze_alert_text("Redis to PostgreSQL connection error",dependency_tag="database")
    assert mixed["family"]=="other"
    assert mixed["basis"]=="ambiguous_alert_text"
    assert set(mixed["candidate_families"])=={"redis","database"}
    negative=analyze_alert_text("No database errors detected",dependency_tag="database")
    assert negative["basis"]=="negative_alert_text"
    assert negative["route"]==""
    assert negative["root_cause_confirmed"] is False


def test_other_service_or_unscoped_log_cannot_control_alert_routes():
    rows=[
        {"source":"zabbix","type":"alert","raw_data":{
            "service":"gfpapi","name":"gfpapi Database connection refused"}},
        {"source":"elasticsearch","type":"log","raw_data":{
            "service":"GFP_Backend","name":"GFP_Backend Kafka error"}},
        {"source":"zabbix","type":"alert","raw_data":{
            "name":"OtherBackend Database connection refused"}},
        {"source":"zabbix","type":"alert","raw_data":{
            "name":"GFP_Backend Redis timeout"}},
    ]
    assert TriageAgent._declared_dependency_routes(rows,"GFP_Backend")==["dependency"]
    assert TriageAgent._declared_dependency_routes(rows,"") == []


def test_prometheus_alertmanager_annotation_title_is_analyzed():
    evidence=[{"source":"prometheus","type":"metric","reference":"am-29","raw_data":{
        "prometheus_alert_kind":"alertmanager",
        "labels":{"service":"GFP_Backend","dependency":"redis"},
        "annotations":{"summary":"GFP_Backend Kafka broker failures reached threshold"},
    }}]
    intents=received_alert_intents(evidence,"GFP_Backend")
    assert len(intents)==1
    assert intents[0]["route"]=="messaging"
    assert intents[0]["tag_conflict"] is True


def test_original_alert_text_selects_database_first_in_low_confidence_triage():
    title="GFP_Backend database connection errors reached at least 10 events"
    evidence=[{"source":"zabbix","type":"alert","raw_data":{
        "service":"GFP_Backend","name":title,
    }}]
    intents=received_alert_intents(evidence,"GFP_Backend")
    result=IncidentCoordinator.select_agents({
        "confidence":0.2,
        "handoff_agents":["network","vm","infrastructure"],
        "analysis_details":{
            "primary_domain":"network",
            "specialist_routes":["network","vm","infrastructure"],
            "alert_dependency_routes":[intent["route"] for intent in intents],
            "alert_text_intents":intents,
            "routing_confidence_band":"low",
        },
    },{"database","network","vm","infrastructure","dependency"})
    assert result["selected"][0]=="database"


def test_operator_report_retains_received_text_and_explains_tag_conflict():
    title="GFP_Backend database connection errors reached at least 10 events in the last 2 minutes"
    report=build_alert_focused_report(
        {"summary":title,"service":"GFP_Backend","context":{"source":"zabbix"}},
        [{"id":"alert-01","source":"zabbix","created_at":"2026-10-20T07:37:07Z",
          "raw_data":{
              "signal_type":title,"signal_summary":title,
              "name":title,"service":"GFP_Backend",
              "tags":[{"tag":"dependency","value":"redis"}],
          }}],
        {"mcp_evidence":[],"agent_findings":[]},
    )
    assert report["source_basis"]=="received_signal"
    assert report["alert_message"]==title
    assert report["reported_service"]=="GFP_Backend"
    assert report["family"]=="database"
    assert report["alert_text_analysis"]["tag_conflict"] is True
    assert report["alert_text_analysis"]["condition"]=="error_threshold"
    assert report["related_checks"]==[]
    assert report["root_cause_confirmed"] is False
