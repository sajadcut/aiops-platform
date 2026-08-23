# ============================================================
# FILE: tests/test_five_steps.py
# ============================================================

import asyncio

from apps.execution_service.tools.registry import tool_registry
from apps.execution_service.tools.mock_executor import MockExecutorTool

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
        "AI OPS - NEXT 5 STAGES TEST"
    )
    print(
        "========================================"
    )

    # ========================================================
    # STEP 1 - TOOL REGISTRATION
    # ========================================================

    tool_registry.register(
        MockExecutorTool()
    )

    assert (
        "mock_executor"
        in tool_registry.list_tools()
    )

    print(
        "\n[1/5] Tool Registry: PASS"
    )

    # ========================================================
    # STEP 2 - APPROVAL
    # ========================================================

    approval = (
        ApprovalService.create_request(
            incident_id="test-incident",
            action="investigate",
            risk_level="low",
            approver="Team-Lead",
        )
    )

    assert (
        approval["status"]
        == "pending"
    )

    approval = (
        ApprovalService.approve(
            approval["approval_id"]
        )
    )

    assert (
        approval["status"]
        == "approved"
    )

    print(
        "[2/5] Approval Flow: PASS"
    )

    # ========================================================
    # STEP 3 - EXECUTION
    # ========================================================

    request = ExecutionRequest(
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
        approval_id=approval[
            "approval_id"
        ],
    )

    execution = (
        await ExecutionService.execute(
            request
        )
    )

    assert execution.success is True
    assert execution.result is not None

    print(
        "[3/5] Execution Service: PASS"
    )

    # ========================================================
    # STEP 4 - VERIFICATION
    # ========================================================

    before_context = {
        "summary": {
            "error_rate": 15.6,
            "avg_cpu": 75,
            "avg_memory": 85,
        }
    }

    after = (
        execution.result["after"]
    )

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

    print(
        "[4/5] Verification Engine: PASS"
    )

    # ========================================================
    # STEP 5 - END TO END RESULT
    # ========================================================

    print(
        "\nExecution:"
    )

    print(
        execution.model_dump()
    )

    print(
        "\nVerification:"
    )

    print(
        verification.model_dump()
    )

    print(
        "\n========================================"
    )
    print(
        "ALL 5 STAGES: PASS"
    )
    print(
        "========================================\n"
    )


if __name__ == "__main__":
    asyncio.run(main())