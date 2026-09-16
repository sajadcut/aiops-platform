import json

import pytest

from agents.network import NetworkAgent
from agents.network.engine import build_network_reliability_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def metric(eid, name, value, *, source_host="api-a", destination_host="db-b", protocol="tcp", port=5432, **raw):
    return {
        "id": eid,
        "type": "metric",
        "source": "prometheus",
        "name": name,
        "value": value,
        "raw_data": {
            "source_host": source_host,
            "destination_host": destination_host,
            "protocol": protocol,
            "destination_port": port,
            **raw,
        },
    }


def telemetry(eid, diagnostic, *, source_host="api-a", destination_host="db-b", protocol="tcp", port=5432, source="vm_telemetry", **raw):
    return {
        "id": eid,
        "type": "telemetry",
        "source": source,
        "raw_data": {
            "diagnostic": diagnostic,
            "source_host": source_host,
            "destination_host": destination_host,
            "protocol": protocol,
            "destination_port": port,
            **raw,
        },
    }


def analyze(evidence):
    return build_network_reliability_analysis(
        evidence,
        service_name="payments",
        context={"time_range": {"start": "2026-09-16T10:00:00Z", "end": "2026-09-16T10:05:00Z"}},
    )


def codes(result):
    return {row["code"] for row in result["cause_candidates"]}


def candidate(result, code):
    return next(row for row in result["cause_candidates"] if row["code"] == code)


def test_dns_nxdomain_is_localized_to_source_destination_and_not_generic_timeout():
    result = analyze([
        telemetry(
            "dns",
            "dns_lookup",
            destination_host="orders.internal",
            protocol="udp",
            port=53,
            dns_status="NXDOMAIN",
            resolver="10.0.0.53",
            query_name="orders.internal",
        )
    ])
    row = candidate(result, "dns")
    assert row["source"] == "api-a"
    assert row["destination"] == "orders.internal"
    assert row["protocol"] == "udp"
    assert row["port"] == 53
    assert row["time_window"]["start"] == "2026-09-16T10:00:00Z"
    assert "NXDOMAIN" in row["expected_falsification_result"]


def test_packet_loss_and_retransmission_create_path_level_packet_loss_candidate():
    result = analyze([
        metric("loss", "network_packet_loss_ratio", 0.08, port=443, destination_host="checkout"),
        metric("retrans", "tcp_retransmission_rate", 0.04, port=443, destination_host="checkout"),
    ])
    row = candidate(result, "packet_loss")
    assert set(row["evidence_ids"]) == {"loss", "retrans"}
    assert row["source"] == "api-a"
    assert row["destination"] == "checkout"
    assert row["root_cause_status"] == "candidate_requires_falsification"


def test_closed_port_is_listener_service_not_routing():
    result = analyze([
        telemetry("route", "route", destination_host="db-b", route_found=True),
        telemetry("listener", "listener", destination_host="db-b", listening=False),
        telemetry("tcp", "tcp_connect", destination_host="db-b", tcp_status="refused"),
    ])
    assert "listener_service" in codes(result)
    assert "routing" not in codes(result)
    assert candidate(result, "listener_service")["handoff"] == "application"


def test_listener_healthy_but_denied_flow_is_firewall_policy_path_break():
    result = analyze([
        telemetry("listener", "listener", destination_host="svc-b", port=8443, listening=True),
        telemetry(
            "flow",
            "ebpf_flow",
            destination_host="svc-b",
            port=8443,
            source="kubernetes",
            verdict="DENIED",
            packets=8,
            service="svc-b",
        ),
    ])
    assert "firewall_policy" in codes(result)
    assert "listener_service" not in codes(result)
    row = candidate(result, "firewall_policy")
    assert row["source"] == "api-a"
    assert row["destination"] == "svc-b"
    assert row["port"] == 8443
    assert result["layers"]["flows"][0]["denied"] is True


def test_route_issue_is_distinct_from_destination_listener():
    result = analyze([
        telemetry("route", "route", destination_host="cache-b", port=6379, route_found=False),
        telemetry("gateway", "gateway", destination_host="cache-b", port=6379, gateway_reachable=False),
        telemetry("listener", "listener", destination_host="cache-b", port=6379, listening=True),
    ])
    assert "routing" in codes(result)
    assert "listener_service" not in codes(result)
    assert candidate(result, "routing")["handoff"] == "infrastructure"


def test_tls_identity_issue_requires_tls_evidence_not_tcp_timeout_only():
    result = analyze([
        telemetry("tcp", "tcp_connect", destination_host="auth.internal", port=443, tcp_status="connected"),
        telemetry(
            "tls",
            "tls_handshake",
            destination_host="auth.internal",
            port=443,
            tls_status="failed",
            certificate_error="certificate verify failed: hostname mismatch",
        ),
    ])
    assert "tls_identity" in codes(result)
    row = candidate(result, "tls_identity")
    assert row["handoff"] == "identity"
    assert "TLS" in row["expected_falsification_result"]


def test_application_slow_response_is_not_mislabeled_as_network_fault():
    result = analyze([
        telemetry("route", "route", destination_host="orders", port=443, route_found=True),
        telemetry("reach", "reachability", destination_host="orders", port=443, reachable=True),
        telemetry("dns", "dns_lookup", destination_host="orders", protocol="udp", port=53, dns_status="NOERROR", resolver="10.0.0.53"),
        telemetry("listener", "listener", destination_host="orders", port=443, listening=True),
        telemetry("tcp", "tcp_connect", destination_host="orders", port=443, tcp_status="connected"),
        telemetry("http", "http_request", destination_host="orders", port=443, http_status=200, http_latency_ms=2400),
    ])
    assert "application_timeout" in codes(result)
    row = candidate(result, "application_timeout")
    assert row["handoff"] == "application"
    assert row["root_cause_status"] == "candidate_requires_falsification"
    assert "packet_loss" not in codes(result)
    assert "routing" not in codes(result)


def test_network_healthy_when_path_dns_tcp_and_loss_are_explicitly_healthy():
    result = analyze([
        telemetry("route", "route", destination_host="orders", port=443, route_found=True),
        telemetry("gateway", "gateway", destination_host="orders", port=443, gateway_reachable=True),
        telemetry("reach", "reachability", destination_host="orders", port=443, reachable=True),
        telemetry("dns", "dns_lookup", destination_host="orders", protocol="udp", port=53, dns_status="NOERROR", resolver="10.0.0.53"),
        telemetry("listener", "listener", destination_host="orders", port=443, listening=True),
        telemetry("tcp", "tcp_connect", destination_host="orders", port=443, tcp_status="connected"),
        metric("loss", "network_packet_loss_ratio", 0.0, destination_host="orders", port=443),
        metric("retrans", "tcp_retransmission_rate", 0.0, destination_host="orders", port=443),
    ])
    assert codes(result) == {"network_healthy"}
    assert candidate(result, "network_healthy")["handoff"] == "application"


def test_connection_timeout_alone_is_uncertain_observation_not_network_root_cause():
    result = analyze([
        telemetry("timeout", "tcp_connect", destination_host="orders", port=443, tcp_status="timeout"),
    ])
    assert not result["cause_candidates"]
    assert result["uncertain_observations"][0]["code"] == "connection_timeout_requires_layer_localization"
    assert "not sufficient" in result["uncertain_observations"][0]["interpretation"]


def test_dns_resolver_divergence_is_detected_from_same_source_and_query():
    result = analyze([
        telemetry("dns-a", "dns_lookup", destination_host="orders.internal", protocol="udp", port=53, dns_status="NOERROR", resolver="10.0.0.53", query_name="orders.internal", dns_answer="10.1.0.10"),
        telemetry("dns-b", "dns_lookup", destination_host="orders.internal", protocol="udp", port=53, dns_status="NOERROR", resolver="10.0.0.54", query_name="orders.internal", dns_answer="10.1.0.99"),
    ])
    assert "dns" in codes(result)
    statuses = {row["status"] for row in result["layers"]["dns"]["events"]}
    assert "RESOLVER_MISMATCH" in statuses


class CapturingNetworkLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "network-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        payload = {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["packet loss and retransmission increased on one service path"],
            "affected_components": ["api-a->checkout:443"],
            "probable_dependencies": ["checkout"],
            "blast_radius": "single service path",
            "hypotheses": [{
                "hypothesis": "packet loss on the api-a to checkout path",
                "probability": 0.82,
                "evidence_ids": ["loss", "retrans"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["repeat the same path test while comparing packet loss and retransmission"],
                "impacted_components": ["checkout"],
                "recommended_next_evidence": ["interface drop counters on the same path"],
                "source": "api-a",
                "destination": "checkout",
                "protocol": "tcp",
                "port": 443,
                "time_window": {"start": "2026-09-16T10:00:00Z", "end": "2026-09-16T10:05:00Z"},
                "expected_falsification_result": "loss and retransmission remain normal while the same failure reproduces",
            }],
            "missing_evidence": [],
            "handoff_agents": ["infrastructure"],
            "immediate_checks": ["Inspect route, loss and retransmission for api-a to checkout:443"],
            "confidence": 0.82,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_network_agent_exposes_layered_path_analysis_and_hypothesis_context():
    adapter = CapturingNetworkLLM()
    incident = AgentInput(
        incident_id="inc-network",
        service_name="payments",
        evidence_summary="checkout path degraded",
        time_range={"start": "2026-09-16T10:00:00Z", "end": "2026-09-16T10:05:00Z"},
        context={"evidence": [
            metric("loss", "network_packet_loss_ratio", 0.08, destination_host="checkout", port=443),
            metric("retrans", "tcp_retransmission_rate", 0.04, destination_host="checkout", port=443),
        ]},
    )
    result = await NetworkAgent(adapter).analyze(incident)
    assert "NETWORK_ANALYSIS=" in adapter.prompt
    assert result.analysis_details["network_layers"]["l4"]["tcp_retransmission"] == 0.04
    assert result.analysis_details["path_analysis"]
    hypothesis = result.analysis_details["llm_network_hypotheses"][0]
    assert hypothesis["source"] == "api-a"
    assert hypothesis["destination"] == "checkout"
    assert hypothesis["protocol"] == "tcp"
    assert hypothesis["port"] == 443
    assert hypothesis["time_window"]["start"] == "2026-09-16T10:00:00Z"
    assert hypothesis["expected_falsification_result"]
    assert result.analysis_details["execution_boundary"] == "analysis_only"
    assert all(action.read_only for action in result.recommended_actions)
