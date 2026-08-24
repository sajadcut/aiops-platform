from apps.execution_service.policy import ToolPolicy


def test_production_high_risk_requires_approval():
    assert not ToolPolicy.validate("production", "high", True, True, False)


def test_allowlisted_low_risk_can_run_without_approval_requirement():
    assert ToolPolicy.validate("non-production", "low", True, False, False)


def test_non_allowlisted_tool_is_denied():
    assert not ToolPolicy.validate("non-production", "low", False, False, False)
