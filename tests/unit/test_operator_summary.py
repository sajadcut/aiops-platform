from apps.operator_summary import build_operator_summary


def _service_status(*, active="inactive", sub="dead", result="success", exec_status=0, reference="ev-service"):
    return {
        "id": reference,
        "type": "telemetry",
        "source": "vm_mcp",
        "reference": reference,
        "raw_data": {
            "diagnostic": "service_status",
            "target": "10.100.6.199",
            "service": "nginx",
            "active_state": active,
            "sub_state": sub,
            "result": result,
            "exec_main_status": exec_status,
            "main_pid": 0,
        },
    }


def _base_summary(evidence, *, state=None, approval=None, audit=None, memory=None, findings=None):
    return build_operator_summary(
        incident={"id": "11111111-1111-1111-1111-111111111111", "service": "nginx", "severity": "high"},
        durable_evidence=evidence,
        findings=findings or [],
        checkpoint={"state": state or {}},
        approval=approval,
        audit_events=audit or [],
        memory_entry=memory,
    )


def test_clean_systemd_stop_never_claims_manual_stop_without_direct_evidence():
    summary = _base_summary([_service_status()])

    assert summary["cause_confidence"] == "probable"
    assert summary["cause_confidence_fa"] == "محتمل"
    assert summary["likely_cause"] == (
        "سرویس به‌صورت Clean متوقف شده است؛ توقف دستی محتمل است ولی از شواهد فعلی قابل تأیید نیست."
    )
    assert summary["human_action_indicator"]["status"] == "probable"
    assert "تأیید شده" not in summary["likely_cause"]
    assert "توقف دستی سرویس — تأیید شده" not in summary["summary_fa"]
    assert summary["cause_evidence_ids"] == ["ev-service"]


def test_direct_sudo_journal_evidence_can_confirm_manual_stop():
    journal = {
        "id": "ev-journal",
        "type": "log",
        "source": "vm_mcp",
        "reference": "ev-journal",
        "raw_data": {
            "diagnostic": "system_logs",
            "target": "10.100.6.199",
            "entries": [
                "2026-09-16T07:10:00+00:00 sudo: alice : TTY=pts/2 ; PWD=/home/alice ; COMMAND=/usr/bin/systemctl stop nginx"
            ],
        },
    }
    summary = _base_summary([_service_status(), journal])

    assert summary["cause_confidence"] == "confirmed"
    assert summary["cause_confidence_fa"] == "تأیید شده"
    assert summary["likely_cause"] == "توقف دستی سرویس — تأیید شده"
    assert summary["human_action_indicator"]["type"] == "manual_stop"
    assert summary["human_action_indicator"]["status"] == "confirmed"
    assert "ev-journal" in summary["human_action_indicator"]["evidence_ids"]
    assert {item["evidence_id"] for item in summary["key_evidence"]} >= {"ev-service", "ev-journal"}


def test_agent_manual_stop_claim_is_downgraded_without_direct_evidence():
    finding = {
        "finding_type": "root_cause",
        "statement": "Manual stop by an operator caused the outage",
        "evidence_ids": ["ev-agent-only"],
        "confidence": 0.99,
    }
    summary = _base_summary([], findings=[finding])

    assert summary["cause_confidence"] == "unknown"
    assert summary["human_action_indicator"]["status"] == "unknown"
    assert summary["likely_cause"] == "عامل توقف از شواهد مستقیم فعلی قابل تأیید نیست."


def test_lifecycle_fields_are_recomputed_from_current_checkpoint_and_durable_governance():
    evidence = [
        _service_status(active="active", sub="running", result="success", exec_status=0),
        {
            "id": "ev-process",
            "type": "telemetry",
            "source": "vm_mcp",
            "raw_data": {"diagnostic": "process_status", "target": "10.100.6.199", "running": True, "count": 2},
        },
        {
            "id": "ev-port",
            "type": "telemetry",
            "source": "vm_mcp",
            "raw_data": {"diagnostic": "port_listener_status", "target": "10.100.6.199", "port": 80, "listening": True, "supported": True},
        },
        {
            "id": "ev-tcp",
            "type": "telemetry",
            "source": "vm_mcp",
            "raw_data": {"diagnostic": "tcp_check", "target": "10.100.6.199", "host": "10.100.6.199", "port": 80, "reachable": True, "supported": True},
        },
    ]
    state = {
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "parameters": {"service": "nginx", "target_port": 80},
        },
        "decision": {"action": "require_approval", "risk_level": "high"},
        "execution_result": {
            "success": True,
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "approval_id": "approval-1",
            "result": {"success": True},
        },
        "verification_result": {
            "status": "success",
            "confidence": 0.97,
            "message": "service recovered",
            "evidence_refs": ["ev-service", "ev-process", "ev-port", "ev-tcp"],
        },
    }
    approval = {
        "approval_id": "approval-1",
        "status": "consumed",
        "risk_level": "high",
        "approver": "sre-user",
        "action": "start_service",
        "metadata": {"binding_complete": True, "tool_name": "ssh_vm", "target": "10.100.6.199"},
    }
    audit = [{"event_type": "memory_writeback", "metadata": {"persisted": True, "verification_status": "success"}}]
    summary = _base_summary(
        evidence,
        state=state,
        approval=approval,
        audit=audit,
        memory={"id": "memory-1", "verification_result": "success"},
    )

    assert summary["risk_level"] == "high"
    assert summary["approval_status"] == "consumed"
    assert summary["approver"] == "sre-user"
    assert summary["execution_status"] == "success"
    assert summary["verification_status"] == "success"
    assert summary["memory_status"] == "persisted"
    assert summary["recommended_action"]["tool"] == "ssh_vm"
    assert summary["recommended_action"]["action"] == "start_service"
    assert summary["observed_state"]["port"] == 80
    assert summary["observed_state"]["process_status"]["running"] is True
    assert summary["observed_state"]["port_listener_status"]["listening"] is True
    assert summary["observed_state"]["tcp_check"]["reachable"] is True
    assert summary["source_policy"]["execution_authority"] is False


def test_pending_approval_next_step_does_not_imply_execution_authority():
    summary = _base_summary(
        [_service_status()],
        state={
            "execution_request": {"tool_name": "ssh_vm", "action": "start_service", "target": "10.100.6.199"},
            "decision": {"risk_level": "high", "action": "require_approval"},
        },
        approval={
            "approval_id": "approval-2",
            "status": "pending",
            "risk_level": "high",
            "approver": "sre",
            "action": "start_service",
            "metadata": {"binding_complete": True, "tool_name": "ssh_vm", "target": "10.100.6.199"},
        },
    )

    assert summary["approval_status"] == "pending"
    assert summary["execution_status"] == "not_executed"
    assert "تا قبل از تأیید، عملیاتی اجرا نمی‌شود" in summary["operator_next_step"]


def test_explicit_human_audit_command_can_confirm_manual_stop():
    summary = _base_summary(
        [_service_status()],
        audit=[{
            "event_id": "audit-human-stop",
            "event_type": "operator_command_executed",
            "actor": "alice",
            "action": "stop_service",
            "status": "recorded",
            "metadata": {"actor_type": "human", "command": "systemctl stop nginx"},
        }],
    )

    assert summary["cause_confidence"] == "confirmed"
    assert summary["likely_cause"] == "توقف دستی سرویس — تأیید شده"
    assert "audit-human-stop" in summary["human_action_indicator"]["evidence_ids"]
