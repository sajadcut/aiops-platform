"""Read-only adaptive VM planner and truth-preserving summary regression."""
from datetime import datetime, timezone

import pytest
from apps.chatbot.vm_investigation import run_vm_investigation
from apps.chatbot.vm_result_formatter import render_vm_investigation
from apps.execution_service import ExecutionResult


@pytest.mark.asyncio
async def test_service_down_plan_is_bounded_and_config_check_requires_log_evidence():
    visited = []
    async def fake(request):
        visited.append((request.action, request.parameters))
        data = {"success": True, "target": request.target}
        if request.action == "service_status":
            data["active_state"] = "failed"
        elif request.action == "service_logs":
            data["logs"] = ["configuration error: syntax error in config"]
        elif request.action == "disk_status":
            data["filesystems"] = [{"mount": "/", "use_percent": "98%",
                                    "blocks": "100000", "used": "98000", "available": "2000"}]
        return ExecutionResult(success=True, tool_name=request.tool_name, action=request.action,
                               target=request.target, result=data,
                               execution_completed_at=datetime.now(timezone.utc))
    report = await run_vm_investigation(target="vm1", scope="service_start_failure",
                                        service="gfpapi", execute=fake)
    assert report["read_only"] and not report["root_cause_confirmed"]
    assert len(visited) == 7 and visited[-1][0] == "config_validate"
    assert all(name in {"service_status", "service_logs", "service_runtime_discovery",
                        "process_status", "collect_vm_metrics", "disk_status", "config_validate"}
               for name, _ in visited)
    summary = render_vm_investigation({"result": report})
    assert "failed" in summary and "98%" in summary
    assert "Recovery تأیید نشده" in summary


@pytest.mark.asyncio
async def test_cannot_equate_active_systemd_with_healthy_application():
    async def fake(request):
        data = {"success": True, "target": request.target}
        if request.action == "service_status":
            data["active_state"] = "active"
        if request.action == "service_logs":
            data["logs"] = []
        return ExecutionResult(success=True, tool_name=request.tool_name,
                               action=request.action, target=request.target, result=data)
    report = await run_vm_investigation(target="vm1", scope="service_start_failure",
                                        service="gfpapi", execute=fake)
    assert report["application_health_verified"] is False
    assert report["root_cause_confirmed"] is False
    assert report["steps_executed"] == 6
    assert "Recovery تأیید نشده" in render_vm_investigation({"result": report})


@pytest.mark.asyncio
async def test_partial_errors_are_visible_without_leaking_exception_contents():
    async def fake(request):
        if request.action == "disk_status":
            raise RuntimeError("private-token-very-secret")
        return ExecutionResult(success=False, tool_name=request.tool_name,
                               action=request.action, target=request.target, error="unavailable")
    report = await run_vm_investigation(target="vm1", scope="host_performance", execute=fake)
    assert report["partial"] is True and report["success"] is False
    answer = render_vm_investigation({"result": report})
    assert "private-token" not in answer
    assert "ناقص" in answer


def test_invalid_scope_fails_closed():
    import asyncio
    with pytest.raises(ValueError):
        asyncio.run(run_vm_investigation(target="vm1", scope="execute_arbitrary_command"))
