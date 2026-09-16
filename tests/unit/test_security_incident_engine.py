import json

import pytest

from agents.security import SecurityAgent
from agents.security.enrichment import build_security_incident_analysis
from agents.security.safety import security_prompt_evidence
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def log(evidence_id, message, *, source="elasticsearch", timestamp=None, **raw):
    item = {"id": evidence_id, "type": "log", "source": source, "message": message, "raw_data": raw}
    if timestamp:
        item["timestamp"] = timestamp
    return item


def test_failed_login_storm_is_observed_not_confirmed_compromise():
    evidence = [
        log(
            f"login-{index}", "authentication failed invalid password",
            timestamp=f"2026-09-16T10:0{index}:00Z", user="alice",
            source_ip=f"198.51.100.{index + 10}", service="payments-api",
        )
        for index in range(6)
    ]
    result = build_security_incident_analysis(evidence, service_name="payments-api")
    assert result["authentication_failure_trend"]["count"] == 6
    assert result["authentication_failure_trend"]["source_count"] == 6
    assert result["classification"]["level"] == "observed_suspicious_event"
    assert result["classification"]["single_alert_can_confirm_compromise"] is False
    assert result["mitre_style_mapping"]["status"] == "hypothesis_only"


def test_expired_token_is_false_positive_candidate_not_credential_theft():
    result = build_security_incident_analysis([
        log("expired", "401 authentication failed: JWT expired token", user="svc-payments", service="payments-api"),
    ])
    explanations = [row["explanation"] for row in result["false_positive_analysis"]]
    assert any("expired" in value for value in explanations)
    assert result["classification"]["level"] != "confirmed_compromise"
    assert any(row["code"] == "token_or_service_account_metadata_event" for row in result["security_events"])


def test_misconfigured_rbac_stays_policy_violation_without_attack_claim():
    result = build_security_incident_analysis([
        log("rbac", "403 forbidden by RBAC: misconfigured RBAC missing rolebinding", user="deployer", service="orders"),
    ])
    assert result["authorization_denial_trend"]["count"] == 1
    assert result["classification"]["level"] == "policy_violation"
    assert any("RBAC" in row["explanation"] for row in result["false_positive_analysis"])
    assert result["mitre_style_mapping"]["status"] == "hypothesis_only"


def test_suspicious_process_and_privilege_signals_build_structured_hypothesis():
    result = build_security_incident_analysis([
        log(
            "proc", "unexpected binary process execution execve followed by privilege escalation root shell",
            source="edr", host="vm-payments-1", user="appuser", service="payments-api",
        ),
    ])
    codes = {row["code"] for row in result["security_events"]}
    assert {"suspicious_process_execution", "privilege_escalation_indicator"}.issubset(codes)
    assert result["classification"]["level"] == "probable_attack"
    hypothesis = next(row for row in result["security_hypotheses"] if "privilege" in row["hypothesis"])
    assert hypothesis["supporting_evidence_ids"] == ["proc"]
    assert hypothesis["affected_assets"] == ["vm-payments-1"]
    assert hypothesis["alternative_benign_explanations"]
    assert hypothesis["required_verification"]


def test_process_tree_uses_pid_parent_relationship_without_inventing_maliciousness():
    evidence = [
        log(
            "parent", "process execution observed", source="edr", timestamp="2026-09-16T10:00:00Z",
            host="vm-a", user="svc", process={"pid": 100, "name": "python", "executable": "/usr/bin/python"},
        ),
        log(
            "child", "unexpected binary process execution", source="edr", timestamp="2026-09-16T10:00:02Z",
            host="vm-a", user="svc", process={
                "pid": 120, "ppid": 100, "name": "helper", "executable": "/tmp/helper",
                "hash": {"sha256": "abc123"},
            },
        ),
    ]
    result = build_security_incident_analysis(evidence)
    process = result["process_tree_analysis"]
    assert process["process_count"] == 2
    assert process["parent_child_edges"] == [{
        "asset": "vm-a", "parent_pid": "100", "parent_name": "python",
        "child_pid": "120", "child_name": "helper", "evidence_ids": ["parent", "child"],
    }]
    assert process["suspicious_process_evidence_ids"] == ["child"]
    assert "attribution requires provenance" in process["policy"]


def test_network_scan_like_activity_is_aggregated_across_destinations():
    evidence = [
        log(
            f"net-{index}", "outbound connection attempt", source="flow",
            source_ip="10.0.0.7", destination_ip=f"203.0.113.{index + 1}", destination_port=443, host="vm-a",
        )
        for index in range(9)
    ]
    result = build_security_incident_analysis(evidence)
    assert result["network_analysis"]["scan_candidates"]
    candidate = result["network_analysis"]["scan_candidates"][0]
    assert candidate["unique_destination_count"] == 9
    assert set(candidate["evidence_ids"]) == {f"net-{i}" for i in range(9)}
    assert "network" in result["handoff_candidates"]
    assert result["classification"]["level"] != "confirmed_compromise"


def test_duplicate_noisy_logs_are_false_positive_signal_not_independent_events():
    evidence = [log(f"noise-{index}", "authorization denied retrying request", user="health-check") for index in range(7)]
    result = build_security_incident_analysis(evidence)
    explanations = [row["explanation"] for row in result["false_positive_analysis"]]
    assert any("duplicate logs" in value for value in explanations)
    noisy = next(row for row in result["false_positive_analysis"] if "duplicate logs" in row["explanation"])
    assert noisy["duplicate_count"] == 7
    assert set(noisy["evidence_ids"]) == {f"noise-{index}" for index in range(7)}
    assert result["classification"]["level"] in {"policy_violation", "observed_suspicious_event"}


def test_identity_network_application_timeline_correlation_is_scope_overlap_not_causation():
    evidence = [
        log(
            "id-app", "401 authentication failed for HTTP request", source="application",
            timestamp="2026-09-16T10:00:00Z", user="alice", service="payments-api", host="vm-a",
        ),
        log(
            "net", "network outbound connection timeout", source="flow",
            timestamp="2026-09-16T10:01:00Z", user="alice", service="payments-api", host="vm-a",
            source_ip="10.0.0.7", destination_ip="198.51.100.20", destination_port=443,
        ),
        log(
            "late", "HTTP request completed", source="application",
            timestamp="2026-09-16T10:20:00Z", user="alice", service="payments-api", host="vm-a",
        ),
    ]
    result = build_security_incident_analysis(evidence)
    correlation = result["cross_domain_timeline_correlation"]
    assert correlation["correlations"]
    pair = next(row for row in correlation["correlations"] if set(row["evidence_ids"]) == {"id-app", "net"})
    assert {"identity", "network", "application"}.issubset(set(pair["domains"]))
    assert "identity" in pair["shared_dimensions"] and "service" in pair["shared_dimensions"]
    assert not any("late" in row["evidence_ids"] and "id-app" in row["evidence_ids"] for row in correlation["correlations"])
    assert "not causal" in correlation["policy"]


def test_insufficient_evidence_requests_verification_instead_of_attack_label():
    result = build_security_incident_analysis([log("ordinary", "application request completed normally", service="payments-api")])
    assert result["classification"]["level"] == "insufficient_evidence"
    assert result["classification"]["confidence_cap"] <= 0.35
    assert result["security_hypotheses"] == []
    requested = [row["evidence"] for row in result["next_best_evidence"]]
    assert any("authentication" in value for value in requested)
    assert any("host/process" in value for value in requested)


def test_single_alert_text_never_establishes_confirmed_compromise():
    result = build_security_incident_analysis([
        {"id": "alert", "type": "alert", "source": "siem", "message": "confirmed compromise suspected on payments"},
    ])
    assert result["classification"]["level"] != "confirmed_compromise"
    assert result["classification"]["direct_confirmation_source_count"] == 0


def test_confirmed_compromise_requires_independent_high_specificity_sources():
    result = build_security_incident_analysis([
        log("edr", "EDR verdict malicious malware hash match on process", source="edr", host="vm-a"),
        log("forensic", "forensic artifact confirmed compromise confirmed by memory image", source="forensics", host="vm-a"),
    ])
    assert result["classification"]["level"] == "confirmed_compromise"
    assert result["classification"]["direct_confirmation_source_count"] == 2
    assert set(result["classification"]["direct_confirmation_evidence_ids"]) == {"edr", "forensic"}


def test_security_prompt_projection_redacts_secret_token_values_in_keys_and_free_text():
    projected = security_prompt_evidence([
        log(
            "secret", "service account token=SUPER-SECRET-TOKEN password:hunter2 Bearer abc.def.ghi",
            token="RAW-TOKEN", secret="RAW-SECRET", authorization="Bearer another.secret.value",
        ),
    ])
    rendered = json.dumps(projected)
    for secret in ("SUPER-SECRET-TOKEN", "hunter2", "RAW-TOKEN", "RAW-SECRET", "another.secret.value"):
        assert secret not in rendered
    assert "[REDACTED]" in rendered


class StaticSecurityLLM(LLMAdapter):
    def __init__(self, payload):
        self.payload = payload

    @property
    def provider_name(self):
        return "static-security"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps(self.payload), model="static-security")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_agent_blocks_llm_compromise_upgrade_and_keeps_containment_approval_required():
    payload = {
        "severity": "critical", "health_status": "degraded",
        "findings": ["confirmed compromise on payments-api"],
        "authentication_signals": ["failed login"], "authorization_signals": [],
        "suspicious_signals": ["confirmed compromise"], "exposure_signals": [], "policy_signals": [],
        "affected_components": ["payments-api"],
        "hypotheses": [{
            "hypothesis": "confirmed credential theft", "probability": 0.99, "evidence_ids": ["login"],
            "conflicting_evidence_ids": [], "falsification_checks": ["check identity audit"],
            "recommended_next_evidence": ["identity audit"], "alternative_benign_explanations": ["expired credential"],
            "required_verification": ["verify successful session from same source"],
            "affected_identities": ["alice"], "affected_assets": ["payments-api"],
        }],
        "missing_evidence": [], "handoff_agents": [], "immediate_checks": ["Inspect identity audit"],
        "containment_recommendations": ["Revoke alice sessions and isolate payments host"], "confidence": 0.99,
    }
    result = await SecurityAgent(StaticSecurityLLM(payload)).analyze(AgentInput(
        incident_id="sec-1", service_name="payments-api", evidence_summary="failed login",
        context={"evidence": [log("login", "authentication failed invalid password", user="alice", service="payments-api")]},
    ))
    assert result.analysis_details["security_classification"] == "observed_suspicious_event"
    assert "confirmed compromise" not in result.statement.lower()
    assert "confirmed credential theft" not in result.hypotheses[0].hypothesis.lower()
    assert result.confidence <= result.analysis_details["classification_confidence_cap"]
    containment = [row for row in result.recommended_actions if row.purpose == "containment"]
    assert containment
    assert all(row.requires_approval and not row.read_only for row in containment)
    assert result.analysis_details["execution_boundary"] == "analysis_only"


@pytest.mark.asyncio
async def test_identity_network_application_peer_findings_are_auxiliary_and_require_live_link():
    payload = {
        "severity": "medium", "health_status": "degraded", "findings": ["authentication anomaly"],
        "authentication_signals": ["401 spike"], "authorization_signals": [], "suspicious_signals": [],
        "exposure_signals": [], "policy_signals": [], "affected_components": ["payments-api"],
        "hypotheses": [], "missing_evidence": [], "handoff_agents": [],
        "immediate_checks": ["inspect identity audit"], "containment_recommendations": [], "confidence": 0.5,
    }
    context = {
        "evidence": [log("auth-live", "401 authentication failed", user="alice", service="payments-api")],
        "summary": {"peer_operational_context": {"findings": [
            {"agent_name": "identity", "statement": "issuer mismatch possible", "evidence_ids": ["auth-live"], "confidence": 0.99},
            {"agent_name": "network", "statement": "network cause", "evidence_ids": ["not-live"], "confidence": 0.99},
            {"agent_name": "application", "statement": "app observes 401s", "evidence_ids": ["auth-live"], "confidence": 0.99},
        ]}},
    }
    result = await SecurityAgent(StaticSecurityLLM(payload)).analyze(AgentInput(
        incident_id="sec-peer", service_name="payments-api", evidence_summary="401 spike", context=context,
    ))
    peer = result.analysis_details["peer_security_context"]
    assert peer["policy"].startswith("peer_output_is_auxiliary_only")
    assert {row["agent_name"] for row in peer["findings"]} == {"identity", "network", "application"}
    assert "identity" in result.handoff_agents
    assert "application" in result.handoff_agents
    unverified_network = next(row for row in peer["findings"] if row["agent_name"] == "network")
    assert unverified_network["validation_status"] == "unverified_peer_analysis"
