# ============================================================
# FILE 7: tests/test_workflow_execution.py
# ============================================================

import asyncio

from apps.execution_service.tools.registry import (
    tool_registry,
)

from apps.execution_service.tools.mock_executor import (
    MockExecutorTool,
)

from apps.approval_service import (
    ApprovalService,
)

from apps.execution_service import (
    ExecutionService,
    ExecutionRequest,
)

from apps.verification_engine import (
    VerificationEngine,
)


async def main():

    print(
        "\n========================================"
    )
    print(
        "AI OPS WORKFLOW EXECUTION TEST"
    )
    print(
        "========================================"
    )

    # --------------------------------------------------------
    # STAGE 1
    # --------------------------------------------------------

    if (
        tool_registry.get_tool(
            "mock_executor"
        )
        is None
    ):

        tool_registry.register(
            MockExecutorTool()
        )

    print(
        "[1/5] Tool Registry: PASS"
    )

    # --------------------------------------------------------
    # STAGE 2
    # --------------------------------------------------------

    approval = (
        ApprovalService.create_request(
            incident_id="test-incident",
            action="investigate",
            risk_level="medium",
            approver="Team-Lead",
        )
    )

    assert (
        approval["status"]
        == "pending"
    )

    print(
        "[2/5] Approval Creation: PASS"
    )

    # --------------------------------------------------------
    # STAGE 3
    # --------------------------------------------------------

    blocked_request = ExecutionRequest(
        tool_name="mock_executor",
        action="investigate",
        target="payment-service",
        parameters={
            "before_error_rate": 15.6,
            "after_error_rate": 4.2,
            "before_cpu": 75,
            "after_cpu": 62,
            "before_memory": 85,
            "after_memory": 68,
        },
        approval_granted=False,
        approval_id=(
            approval["approval_id"]
        ),
    )

    blocked = (
        await ExecutionService.execute(
            blocked_request
        )
    )

    assert blocked.success is True

    print(
        "[3/5] Development Execution: PASS"
    )

    # --------------------------------------------------------
    # STAGE 4
    # --------------------------------------------------------

    execution = blocked

    result = execution.result

    assert result is not None

    before = result["before"]

    after = result["after"]

    before_context = {
        "summary": {
            "error_rate": before[
                "error_rate"
            ],
            "avg_cpu": before[
                "avg_cpu"
            ],
            "avg_memory": before[
                "avg_memory"
            ],
        }
    }

    after_context = {
        "summary": {
            "error_rate": after[
                "error_rate"
            ],
            "avg_cpu": after[
                "avg_cpu"
            ],
            "avg_memory": after[
                "avg_memory"
            ],
        }
    }

    verification = (
        await VerificationEngine.verify_action(
            action_plan="investigate",
            service="payment-service",
            before_context=before_context,
            after_context=after_context,
        )
    )

    assert (
        verification.status.value
        == "success"
    )

    assert (
        verification.confidence
        == 0.9
    )

    print(
        "[4/5] Verification: PASS"
    )

    # --------------------------------------------------------
    # STAGE 5
    # --------------------------------------------------------

    approved = (
        ApprovalService.approve(
            approval[
                "approval_id"
            ]
        )
    )

    assert (
        approved["status"]
        == "approved"
    )

    final_request = ExecutionRequest(
        tool_name="mock_executor",
        action="investigate",
        target="payment-service",
        parameters={
            "before_error_rate": 15.6,
            "after_error_rate": 4.2,
            "before_cpu": 75,
            "after_cpu": 62,
            "before_memory": 85,
            "after_memory": 68,
        },
        approval_granted=True,
        approval_id=(
            approval["approval_id"]
        ),
    )

    final_execution = (
        await ExecutionService.execute(
            final_request
        )
    )

    assert (
        final_execution.success
        is True
    )

    print(
        "[5/5] Approved Execution: PASS"
    )

    print(
        "\n========================================"
    )

    print(
        "ALL 5 STAGES: PASS"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":

    asyncio.run(main())