from pathlib import Path

from agents.shared.base import AgentInput
from agents.shared.domain_agent import DomainDiagnosticAgent
from apps.decision_engine import DecisionAction, DecisionEngine, RiskLevel
from apps.verification_service import VerificationEngine, VerificationStatus
from integrations.prometheus.client import PrometheusClient


def _finding(confidence: float = 0.9):
    return {"agent_name": "application", "confidence": confidence}


def test_decision_uses_execution_action_and_tool_risk_over_benign_plan():
    result = DecisionEngine.evaluate_plan(
        "Review current evidence and monitor the service.",
        [_finding()],
        execution_request={"tool_name": "ssh_vm", "action": "restart_service", "target": "vm01"},
        tool_risk_level="high",
        tool_requires_approval=True,
        tool_exists=True,
    )
    assert result.risk_level == RiskLevel.HIGH
    assert result.action == DecisionAction.REQUIRE_APPROVAL
    assert result.metadata["tool_risk"] == "high"
    assert result.metadata["execution_action"] == "restart_service"


def test_decision_rejects_unknown_requested_tool():
    result = DecisionEngine.evaluate_plan(
        "Check service status.",
        [_finding()],
        execution_request={"tool_name": "does_not_exist", "action": "status", "target": "vm01"},
        tool_exists=False,
    )
    assert result.action == DecisionAction.REJECT
    assert "not registered" in result.reason


def test_peer_context_is_bounded_and_never_live_evidence():
    inp = AgentInput(
        incident_id="inc-1",
        evidence_summary="500 spike",
        service_name="payments",
        context={
            "evidence": [{"source": "prometheus", "reference": "metric-1", "type": "metric"}],
            "summary": {
                "peer_operational_context": {
                    "findings": [{
                        "agent_name": "application",
                        "statement": "database may be saturated",
                        "confidence": 0.9,
                        "evidence_ids": ["metric-1"],
                        "hypotheses": [{"hypothesis": "db saturation"}],
                    }],
                    "coordination": {"disagreement": True, "agreement_score": 0.5},
                }
            },
        },
    )
    peer = DomainDiagnosticAgent._peer_context(inp)
    assert peer["findings"][0]["agent_name"] == "application"
    assert peer["coordination"]["disagreement"] is True
    assert len(DomainDiagnosticAgent.evidence_items(inp)) == 1
    assert DomainDiagnosticAgent.evidence_items(inp)[0]["reference"] == "metric-1"


def _context(metrics):
    return {
        "live_evidence": {
            "evidence": [
                {
                    "type": "metric",
                    "source": "prometheus",
                    "reference": f"{name}-{index}",
                    "raw_data": {"name": name, "value": value},
                }
                for index, (name, value) in enumerate(metrics)
            ]
        }
    }


async def test_verification_respects_metric_direction_and_aggregates_samples():
    before = _context([
        ("error_rate", 20), ("error_rate", 10),
        ("up", 0), ("throughput", 50),
    ])
    after = _context([
        ("error_rate", 4), ("error_rate", 6),
        ("up", 1), ("throughput", 100),
    ])
    result = await VerificationEngine.verify_action("recover", "payments", before, after)
    assert result.status == VerificationStatus.SUCCESS
    assert result.before_state["error_rate"] == 15.0
    assert result.after_state["error_rate"] == 5.0
    assert result.metric_directions["up"] == "higher_is_better"
    assert result.metric_directions["error_rate"] == "lower_is_better"


async def test_verification_does_not_call_lower_throughput_an_improvement():
    before = _context([("throughput", 100)])
    after = _context([("throughput", 10)])
    result = await VerificationEngine.verify_action("recover", "payments", before, after)
    assert result.status == VerificationStatus.FAILED


def test_prometheus_queries_common_service_label_conventions_and_escape_values():
    queries = PrometheusClient._metric_queries("error_rate", 'pay"ments')
    assert len(queries) == 3
    assert 'service="pay\\"ments"' in queries[0]
    assert any("service_name=" in query for query in queries)
    assert any("app=" in query for query in queries)


def test_offline_dockerfile_fails_closed_and_runs_non_root():
    text = Path("deployment/docker/offline/Dockerfile").read_text()
    assert "|| true" not in text
    assert "python:3.12-slim" in text
    assert "USER 10001:10001" in text
    assert "pip check" in text


def test_kubernetes_manifest_has_availability_and_security_guards():
    text = Path("deployment/kubernetes/aiops-platform.yaml").read_text()
    for required in (
        "kind: PodDisruptionBudget",
        "maxUnavailable: 0",
        "topologySpreadConstraints:",
        "automountServiceAccountToken: false",
        "readOnlyRootFilesystem: true",
        'drop: ["ALL"]',
        "resources:",
        "seccompProfile:",
    ):
        assert required in text
    assert ":latest" not in text
