from apps.decision_engine import DecisionAction, DecisionEngine


def _finding():
    return {"agent_name": "kubernetes", "confidence": 0.95}


def test_decision_rejects_write_when_target_identity_is_only_knowledge_assisted():
    result = DecisionEngine.evaluate_plan(
        "Restart the affected Kubernetes workload after approval.",
        [_finding()],
        execution_request={
            "tool_name": "kubernetes_mcp",
            "action": "restart_kubernetes_workload",
            "target": "web-api",
        },
        tool_risk_level="high",
        tool_requires_approval=True,
        tool_exists=True,
        target_identity_verified=False,
    )
    assert result.action == DecisionAction.REJECT
    assert result.requires_approval is False
    assert result.metadata["target_identity_verified"] is False
    assert "Live Evidence" in result.reason


def test_decision_allows_normal_policy_after_live_target_verification():
    result = DecisionEngine.evaluate_plan(
        "Restart the affected Kubernetes workload after approval.",
        [_finding()],
        execution_request={
            "tool_name": "kubernetes_mcp",
            "action": "restart_kubernetes_workload",
            "target": "web-api",
        },
        tool_risk_level="high",
        tool_requires_approval=True,
        tool_exists=True,
        target_identity_verified=True,
    )
    assert result.action == DecisionAction.REQUIRE_APPROVAL
    assert result.metadata["target_identity_verified"] is True
