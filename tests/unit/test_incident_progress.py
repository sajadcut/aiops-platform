"""Workflow milestone accuracy, API stream safety and isolation contracts."""
from datetime import datetime, timedelta, timezone

import pytest

from apps.orchestrator.progress import (
    ANALYSIS_STAGES, EXECUTION_STAGES, progress_record, summarize_progress,
)


BASE = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def event(stage, status, seconds):
    return {"metadata": progress_record(stage, status),
            "created_at": BASE + timedelta(seconds=seconds)}


def test_progress_only_advances_on_real_completed_work_not_time_or_source_ping():
    initial = [event("context", "started", 0), event("vm_mcp", "started", 4)]
    a = summarize_progress(initial, incident_status="analyzing")
    assert a["analysis_percent"] == 0
    assert a["current_stage"] == "context"
    assert a["providers"]["vm_mcp"]["status"] == "started"
    assert a["time_estimate_available"] is False
    # Merely increasing timestamp/time does NOT change progress.
    b = summarize_progress(initial + [event("vm_mcp", "completed", 40)])
    assert b["analysis_percent"] == 0
    c = summarize_progress(initial + [event("context", "completed", 80)])
    assert c["analysis_percent"] == round(100 / len(ANALYSIS_STAGES))
    assert c["analysis_total"] == 6
    assert c["percent_represents"] == "observed_stage_completion_not_elapsed_time"


def test_stage_failure_does_not_fabricate_completion():
    events = [event("context", "started", 0), event("context", "completed", 3),
              event("triage", "started", 4), event("triage", "failed", 8)]
    result = summarize_progress(events, checkpoint_status="failed")
    assert result["analysis_percent"] == 17
    assert result["stages"]["triage"]["status"] == "failed"
    assert result["analysis_completed"] == 1


def test_real_finished_path_has_100_percent_and_no_pending_node():
    rows = [event("context", "started", 0)]
    for index, stage in enumerate(ANALYSIS_STAGES):
        rows.append(event(stage, "completed", 10 + index))
    rows.append(event("approval", "started", 20))
    approved = summarize_progress(rows, approval_status="pending",
                                  checkpoint_status="paused")
    assert approved["analysis_percent"] == 100
    assert approved["current_stage"] == "approval"
    assert approved["execution_percent"] == 0
    assert approved["execution_completed"] == 0
    # Approval alone must not fake missing steps.
    partial = summarize_progress(rows[:3], approval_status="pending")
    assert partial["analysis_percent"] < 100


def test_early_evaluator_stop_is_a_complete_attempt_not_unexecuted_decision():
    rows = [event(stage, "completed", i) for i, stage in enumerate(ANALYSIS_STAGES[:-1])]
    rows.append(event("end", "completed", 12))
    final = summarize_progress(rows, checkpoint_status="completed")
    assert final["analysis_completed"] == 5
    assert final["analysis_total"] == 5
    assert final["analysis_percent"] == 100
    assert "decision" not in final["stages"]


def test_execution_and_verification_are_separate_from_prior_analysis():
    rows = [event(stage, "completed", i) for i, stage in enumerate(ANALYSIS_STAGES)]
    rows += [event("execution", "started", 20)]
    executing = summarize_progress(rows, approval_status="consumed")
    assert executing["analysis_percent"] == 100
    assert executing["execution_percent"] == 0
    assert executing["current_stage"] == "execution"
    rows += [event("execution", "completed", 40),
             event("verification", "started", 41)]
    checking = summarize_progress(rows, approval_status="consumed")
    assert checking["execution_completed"] == 1
    assert checking["execution_percent"] == round(100 / len(EXECUTION_STAGES))
    assert checking["current_stage"] == "verification"


def test_untrusted_payload_cannot_insert_commands_or_new_stages():
    with pytest.raises(ValueError, match="invalid_progress_stage"):
        progress_record("rm -rf /", "started")
    with pytest.raises(ValueError, match="invalid_progress_status"):
        progress_record("context", "authorize_delete")
    sanitized = progress_record("zabbix", "completed", provider="zabbix",
                                detail="secret://password-in-log")
    assert sanitized["detail"] == ""
    rows = [{"metadata": {"stage": "sudo-delete", "status": "completed"},
             "created_at": BASE}]
    assert summarize_progress(rows)["stages"] == {}


def test_each_sse_stream_route_uses_read_permission_and_never_runs_workflow():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] / "apps/api/incident_resources.py").read_text()
    assert '@router.get("/incidents/{incident_id}/progress/stream")' in source
    assert "Request" in source and "StreamingResponse" in source
    assert 'Depends(require_permission("read:incident"))' in source
    assert 'X-Accel-Buffering' in source
    assert 'event: progress' in source
    assert 'await load_progress(str(incident_id))' in source
    assert "resume_after_approval" not in source
    assert "execute_tool(" not in source


def test_individual_agents_are_live_observations_not_auto_incremented_percent():
    rows = [event("context", "completed", 1), event("triage", "completed", 2),
            event("parallel_agents", "started", 3),
            event("agent:vm", "started", 4), event("agent:network", "started", 5),
            event("agent:network", "completed", 12), event("agent:storage", "failed", 13)]
    progress = summarize_progress(rows)
    assert progress["current_stage"] == "parallel_agents"
    assert progress["analysis_percent"] == 33
    assert progress["agents"]["vm"]["status"] == "started"
    assert progress["agents"]["network"]["status"] == "completed"
    assert progress["agents"]["storage"]["status"] == "failed"
    assert progress["analysis_completed"] == 2
    # An arbitrary registry/model string cannot control UI markup or stage map.
    with pytest.raises(ValueError):
        progress_record("agent:<script>alert(1)</script>", "started")
