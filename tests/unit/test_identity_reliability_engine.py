import json

import pytest

from agents.identity import IdentityAgent
from agents.identity.engine import build_identity_reliability_analysis
from agents.identity.safety import identity_prompt_evidence, redact_identity_value
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def event(eid, diagnostic, *, message="", source="identity", **raw):
    return {
        "id": eid,
        "type": "log",
        "source": source,
        "message": message,
        "raw_data": {"diagnostic": diagnostic, **raw},
    }


def metric(eid, name, value, **raw):
    return {
        "id": eid,
        "type": "metric",
        "source": "prometheus",
        "name": name,
        "value": value,
        "raw_data": raw,
    }


def analyze(evidence, **context):
    return build_identity_reliability_analysis(
        evidence,
        service_name="payments",
        context={"incident_start": "2026-09-16T10:00:00Z", **context},
    )


def codes(result):
    return {row["code"] for row in result["cause_candidates"]}


def candidate(result, code):
    return next(row for row in result["cause_candidates"] if row["code"] == code)


def stage(result, name):
    return next(row for row in result["authentication_chain"] if row["stage"] == name)


def test_expired_token_is_distinct_claim_time_failure():
    result = analyze([
        event(
            "exp",
            "jwt_validation",
            exp="2026-09-16T09:55:00Z",
            validation_time="2026-09-16T10:01:00Z",
        ),
    ])
    assert "expired_token" in codes(result)
    assert "wrong_audience" not in codes(result)
    assert stage(result, "claims")["status"] == "fail"


def test_wrong_audience_is_separate_from_signature_failure():
    result = analyze([
        event("aud", "jwt_validation", expected_audience="payments-api", audience="other-api"),
        event("sig", "jwt_validation", signature_valid=True),
    ])
    assert "wrong_audience" in codes(result)
    assert "invalid_signature" not in codes(result)
    assert candidate(result, "wrong_audience")["confidence"] >= 0.9


def test_missing_signing_key_is_not_jwks_outage():
    result = analyze([
        event("jwks", "jwks_validation", jwks_reachable=True, key_present=False, kid="rotated-key"),
    ])
    assert "missing_signing_key" in codes(result)
    assert "jwks_unavailable" not in codes(result)
    assert stage(result, "jwks_signature_validation")["status"] == "fail"


def test_jwks_outage_is_dependency_reachability_failure():
    result = analyze([
        event("jwks", "jwks_fetch", message="JWKS unavailable from validator", jwks_reachable=False),
    ])
    assert "jwks_unavailable" in codes(result)
    assert candidate(result, "jwks_unavailable")["handoff"] == "network"


def test_certificate_expiry_is_tls_failure_not_token_failure():
    result = analyze([
        event(
            "cert",
            "tls_handshake",
            certificate_expiry="2026-09-15T00:00:00Z",
            timestamp="2026-09-16T10:01:00Z",
            message="certificate expired during TLS handshake",
        ),
    ])
    assert "tls_certificate_failure" in codes(result)
    assert "expired_token" not in codes(result)
    assert stage(result, "dns_tls")["status"] == "fail"


def test_clock_skew_is_distinct_from_expired_token():
    result = analyze([
        metric("skew", "identity_clock_skew_seconds", 95),
        event("nbf", "jwt_validation", nbf="2026-09-16T10:02:00Z", validation_time="2026-09-16T10:00:30Z"),
    ])
    assert "clock_skew" in codes(result)
    assert "token_not_yet_valid" in codes(result)
    assert "expired_token" not in codes(result)


def test_rbac_denial_after_valid_signature_routes_to_security_and_application_context():
    result = analyze([
        {"id": "403", "type": "log", "source": "gateway", "raw_data": {"status_code": 403}},
        event("sig", "jwt_validation", signature_valid=True),
        event("rbac", "authorization", message="RBAC denied: insufficient role", role_mapping_valid=False, required_role="operator"),
    ])
    assert "insufficient_role" in codes(result)
    assert "healthy_auth" in codes(result)
    assert result["causal_attribution"] == "authorization_mapping_or_policy_candidate"
    assert {"security", "application"}.issubset(set(result["handoff_candidates"]))
    assert stage(result, "jwks_signature_validation")["status"] == "pass"
    assert stage(result, "authorization_role_mapping")["status"] == "fail"


def test_healthy_auth_chain_has_no_fault_candidate():
    result = analyze([
        event("dns", "dns_lookup", resolved=True),
        event("disc", "oidc_discovery", reachable=True),
        event("idp", "token_endpoint", healthy=True),
        event("jwks", "jwks_validation", jwks_reachable=True, key_present=True, kid="k1"),
        event("sig", "jwt_validation", signature_valid=True),
        event("iss", "jwt_validation", configured_issuer="https://idp.example", issuer="https://idp.example"),
        event("aud", "jwt_validation", configured_audience="payments-api", audience="payments-api"),
        event("alg", "jwt_validation", expected_algorithm="RS256", algorithm="RS256"),
        event("role", "authorization", role_mapping_valid=True, required_role="reader"),
    ])
    assert not codes(result)
    assert stage(result, "dns_tls")["status"] == "pass"
    assert stage(result, "oidc_discovery")["status"] == "pass"
    assert stage(result, "token_issuance")["status"] == "pass"
    assert stage(result, "jwks_signature_validation")["status"] == "pass"
    assert stage(result, "claims")["status"] == "pass"
    assert stage(result, "authorization_role_mapping")["status"] == "pass"


def test_jwks_rotation_timeline_is_correlation_not_causal_proof():
    result = analyze([
        event("rotate", "jwks", jwks_rotation_timestamp="2026-09-16T10:01:00Z", jwks_reachable=True, key_present=True),
    ])
    row = result["jwks_signature_analysis"]["rotation_timeline"]["events"][0]
    assert row["ordering"] == "near_incident_start"
    assert "correlation evidence" in row["causal_policy"]


def test_identity_redaction_removes_credentials_jwt_and_private_material():
    dummy_jwt = "eyJabcdefghijk.eyJabcdefghijklmnop.qwertyuiopasdfgh"
    evidence = [{
        "id": "secret",
        "type": "log",
        "source": "gateway",
        "message": f"Authorization: Bearer {dummy_jwt} token={dummy_jwt}",
        "raw_data": {
            "access_token": dummy_jwt,
            "client_secret": "synthetic-secret-value",
            "private_key": "synthetic-private-material",
            "kid": "key-1",
        },
    }]
    projected = json.dumps(identity_prompt_evidence(evidence))
    assert dummy_jwt not in projected
    assert "synthetic-secret-value" not in projected
    assert "synthetic-private-material" not in projected
    assert "key-1" in projected
    assert "REDACTED" in projected
    assert dummy_jwt not in json.dumps(redact_identity_value(evidence))


class CapturingIdentityLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "identity-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        payload = {
            "severity": "medium",
            "health_status": "degraded",
            "findings": ["authorization role mapping is denying access after successful signature validation"],
            "affected_components": ["payments"],
            "probable_dependencies": ["identity-provider"],
            "blast_radius": "authorized operator requests",
            "hypotheses": [{
                "hypothesis": "role mapping denies the required operator role",
                "probability": 0.8,
                "evidence_ids": ["rbac", "sig"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["verify effective role mapping for the affected principal"],
                "impacted_components": ["payments"],
                "recommended_next_evidence": ["credential-safe role mapping decision metadata"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["security", "application"],
            "immediate_checks": ["Inspect effective role mapping and authorization decision metadata"],
            "confidence": 0.8,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_identity_agent_exposes_chain_and_never_prompts_full_credentials():
    adapter = CapturingIdentityLLM()
    dummy_jwt = "eyJabcdefghijk.eyJabcdefghijklmnop.qwertyuiopasdfgh"
    incident = AgentInput(
        incident_id="inc-identity",
        service_name="payments",
        evidence_summary=f"403 after auth; Authorization: Bearer {dummy_jwt}",
        context={"evidence": [
            {"id": "403", "type": "log", "source": "gateway", "raw_data": {"status_code": 403}},
            event("sig", "jwt_validation", signature_valid=True, access_token=dummy_jwt),
            event("rbac", "authorization", message=f"token={dummy_jwt} insufficient role", role_mapping_valid=False, required_role="operator"),
        ]},
    )
    result = await IdentityAgent(adapter).analyze(incident)
    assert "IDENTITY_ANALYSIS=" in adapter.prompt
    assert dummy_jwt not in adapter.prompt
    assert "[REDACTED" in adapter.prompt
    assert result.analysis_details["execution_boundary"] == "analysis_only"
    assert result.analysis_details["credential_redaction"] == "mandatory"
    assert "insufficient_role" in {row["code"] for row in result.analysis_details["cause_candidates"]}
    assert all(action.read_only for action in result.recommended_actions)
