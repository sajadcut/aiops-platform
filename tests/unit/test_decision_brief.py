from datetime import datetime, timedelta, timezone

from apps.decision_brief import CONTRACT_VERSION, build_decision_brief, tool_failed


NOW = datetime(2026, 10, 11, 18, 0, tzinfo=timezone.utc)


def make_brief(*, state=None, evidence=None, approval=None, verification="not_recorded", review=None):
    state = state if state is not None else {
        "triage_result": {
            "agent_name": "triage", "statement": "nginx is unhealthy",
            "confidence": 0.72, "evidence_ids": ["ev-1"],
            "historical_memory_ids": ["mem-1"],
        },
        "analysis_results": [
            {"agent_name": "vm", "statement": "nginx stopped", "confidence": 0.87,
             "evidence_ids": ["ev-1"], "missing_evidence": [], "conflicting_evidence_ids": []}
        ],
        "knowledge_status": {"status": "available"},
        "knowledge_results": [{
            "source_id": "cognia:1:2:3:4", "knowledge_base_id": 1, "knowledge_id": 2,
            "revision_id": 3, "relevance": 0.93, "content": "nginx troubleshooting",
        }],
        "memory_results": [{"id": "mem-1", "incident_id": "old-incident", "action": "restart",
                            "verification_result": "success", "vector_similarity": 0.89}],
        "decision": {"decision": "approve_required", "risk_level": "high"},
        "evaluation": {"confidence": 0.76},
        "coordination": {"agreement_score": 0.5},
    }
    evidence = evidence if evidence is not None else [{
        "id": "ev-1", "source": "vm_mcp", "created_at": NOW.isoformat(),
        "raw_data": {"mcp_server": "vm-mcp", "tool_name": "service_status",
                     "success": True, "summary": "nginx inactive"},
    }]
    summary = {
        "likely_cause": "Service not running", "cause_confidence": "probable",
        "cause_evidence_ids": ["ev-1"], "risk_level": "high",
        "approval": approval if approval is not None else {
            "approval_id": "ap-1", "status": "pending", "binding_complete": True,
            "tool": "vm-mcp", "target": "host-1", "action": "restart_service",
            "environment": "production"},
        "recommended_action": {"action": "restart_service", "tool": "vm-mcp", "target": "host-1"},
        "execution_status": "not_executed",
        "verification_status": verification,
        "verification": {"status": verification, "message": "independent monitor"},
        "memory": {"memory_entry_id": "mem-current"},
    }
    return build_decision_brief(
        incident={"id": "i-1", "service": "nginx", "severity": "high",
                  "status": "analyzing", "summary": "nginx failure"},
        operator_summary=summary,
        checkpoint={"state": state, "version": 7},
        durable_evidence=evidence,
        findings=[],
        audit_events=[],
        knowledge_review=review,
        now=NOW,
    )


def test_brief_is_versioned_read_only_and_snapshot_is_stable():
    left, right = make_brief(), make_brief()
    assert left["contract_version"] == CONTRACT_VERSION
    assert left["snapshot_id"] == right["snapshot_id"]
    assert left["checkpoint_version"] == 7
    assert left["source_policy"]["authorizes_execution"] is False
    assert left["approval_readiness"]["status"] == "human_review_required"
    assert left["approval_readiness"]["binding_complete"] is True
    assert left["localized_narrative"]["llm_used"] is False
    assert "nginx" in left["localized_narrative"]["fa"]


def test_agreement_rca_and_evaluator_are_not_conflated():
    assessment = make_brief()["rca_assessment"]
    assert assessment["rca_confidence"] is None
    assert assessment["evaluator_confidence"] == 0.76
    assert assessment["agent_agreement"] == 0.5


def test_agents_only_report_persisted_runs_and_unverified_knowledge():
    brief = make_brief()
    assert {a["agent"] for a in brief["agent_findings"]} == {"triage", "vm"}
    assert brief["cognia_knowledge"]["items"][0]["use_status"] == "not_verified"
    assert brief["operational_memory"]["items"][0]["use_status"] == "cited_by_agent"
    assert brief["operational_memory"]["historical_not_current_evidence"] is True


def test_contradictions_and_missing_evidence_are_not_suppressed():
    state = {
        "analysis_results": [{
            "agent_name": "vm", "finding_type": "vm_health", "statement": "conflicting",
            "conflicting_evidence_ids": ["ev-2"], "missing_evidence": ["journalctl"],
            "confidence": 0.25,
        }],
        "knowledge_status": {"status": "empty"},
    }
    brief = make_brief(state=state)
    assert brief["agent_findings"][0]["status"] == "partial"
    assert brief["evidence_conflicts"] == ["ev-2"]
    assert "journalctl" in brief["missing_evidence"]
    assert brief["cognia_knowledge"]["status"] == "empty"


def test_failed_agents_are_never_marked_success():
    state = {"analysis_results": [{
        "agent_name": "network", "finding_type": "network_error", "statement": "failed",
        "analysis_details": {"error": "timeout"},
    }]}
    assert make_brief(state=state)["agent_findings"][0]["status"] == "failed"


def test_mcp_http_200_with_internal_failure_is_not_success():
    assert tool_failed({"http_status": 200, "tool_result": {"success": False, "error": "timeout"}})
    evidence = [{
        "id": "ev-2", "source": "prometheus_mcp", "created_at": NOW.isoformat(),
        "raw_data": {"http_status": 200, "mcp_server": "prometheus-mcp",
                     "tool_result": {"success": False, "error": "connection_failure"}},
    }]
    brief = make_brief(evidence=evidence)
    assert brief["mcp_evidence"][0]["status"] == "failed"


def test_stale_evidence_and_missing_monitor_warn_before_approval():
    state = {"live_evidence": {"error": "collector_unavailable"}}
    evidence = [{
        "id": "old", "source": "vm_mcp",
        "created_at": (NOW - timedelta(hours=3)).isoformat(),
        "raw_data": {"mcp_server": "vm", "status": "ok"},
    }]
    brief = make_brief(state=state, evidence=evidence)
    assert brief["data_freshness"] == "stale"
    assert brief["approval_readiness"]["data_freshness"] == "stale"
    assert "live_evidence_collection_failed" in brief["missing_evidence"]


def test_cognia_empty_failed_and_unqueried_are_distinct():
    assert make_brief(state={"knowledge_status": {"status": "empty"}})["cognia_knowledge"]["status"] == "empty"
    assert make_brief(state={"knowledge_status": {"status": "invalid_contract"}})["cognia_knowledge"]["status"] == "failed"
    assert make_brief(state={})["cognia_knowledge"]["status"] == "not_queried"


def test_missing_evidence_and_unknown_confidence_remain_unknown():
    brief = make_brief(state={}, evidence=[])
    assert brief["data_freshness"] == "unknown"
    assert brief["rca_assessment"]["rca_confidence"] is None
    assert "no_durable_evidence" in brief["missing_evidence"]


def test_secrets_redacted_in_nested_tool_messages():
    evidence = [{
        "id": "ev-secret", "source": "vm_mcp", "created_at": NOW.isoformat(),
        "raw_data": {"mcp_server": "vm-mcp", "summary": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
                     "token": "super-secret", "tool_result": {"message": "password=VerySecret123"}},
    }]
    text = str(make_brief(evidence=evidence))
    assert "VerySecret123" not in text
    assert "super-secret" not in text
    assert "abcdefghijklmnopqrstuvwxyz" not in text


def test_review_link_is_only_ready_after_verified_recovery_and_real_draft():
    review = {"id": "draft-1", "status": "pending_review"}
    assert not make_brief(review=review)["knowledge_learning_status"]["review_available"]
    assert make_brief(review=review, verification="success")["knowledge_learning_status"]["review_available"]
    assert not make_brief(verification="success")["knowledge_learning_status"]["review_available"]


def test_rejected_approval_does_not_become_approval_ready():
    brief = make_brief(approval={"status": "rejected", "binding_complete": True})
    assert brief["approval_readiness"]["status"] == "not_pending"


def test_snapshot_changes_when_recorded_state_changes():
    before = make_brief()
    after = make_brief(state={"knowledge_status": {"status": "failed"}})
    assert before["snapshot_id"] != after["snapshot_id"]


def test_provider_source_observation_failure_is_not_reported_as_success():
    evidence = [
        {"id": "prom-observation", "source": "prometheus",
         "created_at": NOW.isoformat(),
         "raw_data": {"status": "unavailable", "result_count": 0}},
    ]
    report = make_brief(evidence=evidence)
    assert report["monitoring_sources"][0]["status"] == "unavailable"
    assert report["mcp_evidence"][0]["status"] == "failed"
    assert report["mcp_evidence"][0]["tool"] == "source_observation"


def test_empty_monitoring_query_does_not_prove_source_failure_or_success():
    evidence = [
        {"id": "prom-queried", "source": "prometheus",
         "created_at": NOW.isoformat(),
         "raw_data": {"status": "queried", "result_count": 0}},
    ]
    report = make_brief(evidence=evidence)
    assert report["monitoring_sources"][0]["status"] == "queried"
    assert report["mcp_evidence"][0]["status"] == "queried"


def test_fresh_and_stale_evidence_do_not_report_all_fresh():
    evidence = [
        {"id": "new", "source": "vm_mcp", "created_at": NOW.isoformat(),
         "raw_data": {"mcp_server": "vm", "success": True}},
        {"id": "old", "source": "vm_mcp",
         "created_at": (NOW - timedelta(hours=2)).isoformat(),
         "raw_data": {"mcp_server": "vm", "success": True}},
    ]
    report = make_brief(evidence=evidence)
    assert report["data_freshness"] == "mixed"
    assert report["approval_readiness"]["data_freshness"] == "mixed"


def test_safe_timeline_does_not_expose_raw_audit_metadata():
    from apps.decision_brief import build_decision_brief
    report = build_decision_brief(
        incident={"id": "i-1", "service": "nginx"},
        operator_summary={"approval": {}},
        checkpoint={"state": {}},
        durable_evidence=[], findings=[],
        audit_events=[{"event_id": "audit-1", "event_type": "approval_granted",
                       "actor": "sre", "status": "success",
                       "created_at": NOW.isoformat(),
                       "metadata": {"password": "NeverExpose123"}}],
        now=NOW,
    )
    assert report["timeline"][0]["actor"] == "sre"
    assert "NeverExpose123" not in str(report)


def test_durable_target_projection_is_labeled_and_not_execution_authority():
    from apps.decision_brief import build_decision_brief
    report = build_decision_brief(
        incident={"id": "i-1", "service": "nginx"},
        operator_summary={"observed_state": {
            "target": "vm.example.local", "port": 443,
            "field_sources": {"target": "service_status"},
            "service_status": {"active_state": "inactive", "evidence_id": "ev-1"},
        }, "approval": {
            "status": "pending", "binding_complete": True,
            "binding_digest": "digest-1", "rollback_supported": False,
        }},
        checkpoint={"state": {}}, durable_evidence=[], findings=[],
        audit_events=[], now=NOW,
    )
    assert report["incident_summary"]["target"] == "vm.example.local"
    assert report["incident_summary"]["observed_service_state"]["service_status"]["active_state"] == "inactive"
    assert report["approval_readiness"]["binding_digest"] == "digest-1"
    assert report["approval_readiness"]["evidence_snapshot_binding"] == "not_verified"
    assert report["source_policy"]["authorizes_execution"] is False


def test_persian_fallback_translates_operational_statuses_without_raw_json():
    report = make_brief()
    prose = report["localized_narrative"]["fa"]
    assert "در حال تحلیل" in prose
    assert "در دسترس" in prose
    assert "ریسک اقدام: زیاد" in prose
    assert "وضعیت تأیید: در انتظار تأیید" in prose
    assert "Cognia: available" not in prose
    assert '"status":' not in prose


def test_complete_nginx_vm_cognia_memory_exposes_operator_decision_context():
    report = make_brief()
    assert report["incident_summary"]["valid_evidence_count"] == 1
    assert report["incident_summary"]["observed_sources"] == 1
    assert report["mcp_evidence"][0]["tool"] == "service_status"
    assert report["cognia_knowledge"]["retrieved_count"] == 1
    assert report["cognia_knowledge"]["items"][0]["use_status"] == "not_verified"
    assert report["operational_memory"]["items"][0]["similarity"] == 0.89
    assert report["approval_readiness"]["status"] == "human_review_required"


def test_previously_unverified_agent_cannot_be_shown_as_success():
    report = make_brief(state={
        "analysis_results": [
            {"agent_name": "network", "status": "skipped", "statement": "Skipped"},
            {"agent_name": "storage", "status": "failed", "statement": "Timed out"},
            {"agent_name": "application", "status": "partial", "statement": "Degraded"},
        ],
        "knowledge_status": {"status": "not_queried"},
    })
    assert [x["status"] for x in report["agent_findings"]] == [
        "skipped", "failed", "partial",
    ]


def test_missing_or_invalid_incident_start_does_not_break_legacy_report():
    for timestamp in ("not-a-time", "2026-10-11T16:00:00", None):
        report = build_decision_brief(
            incident={"id": "i-1", "service": "nginx", "started_at": timestamp},
            operator_summary={}, checkpoint={"state": {}},
            durable_evidence=[], findings=[], audit_events=[], now=NOW,
        )
        assert report["incident_summary"]["elapsed_seconds"] is None
        assert report["source_policy"]["authorizes_execution"] is False


def test_incident_duration_and_kubernetes_identity_are_provenance_only():
    report = build_decision_brief(
        incident={"id": "i-1", "service": "api", "started_at": (NOW-timedelta(minutes=10)).isoformat(),
                  "context": {"kubernetes_namespace": "ns-api", "cluster": "blue-cluster"}},
        operator_summary={}, checkpoint={"state": {}},
        durable_evidence=[], findings=[], audit_events=[], now=NOW,
    )
    assert report["incident_summary"]["elapsed_seconds"] == 600
    assert report["incident_summary"]["namespace"] == "ns-api"
    assert report["incident_summary"]["cluster"] == "blue-cluster"


def test_source_health_query_is_not_counted_as_confirmed_evidence():
    report = make_brief(evidence=[{
        "id": "obs-1", "source": "prometheus", "created_at": NOW.isoformat(),
        "raw_data": {"status": "queried", "result_count": 0},
    }])
    assert report["incident_summary"]["valid_evidence_count"] == 0
    assert report["mcp_evidence"][0]["status"] == "queried"


def test_recorded_execution_failure_verification_and_approver_are_distinct():
    state = {
        "execution_result": {"success": False, "error": "connection_timeout",
                             "tool_name": "vm-mcp", "action": "restart_service",
                             "target": "host-1", "approval_id": "ap-1"},
        "verification_result": {"status": "failed", "confidence": 0.19,
                                "message": "port still closed", "evidence_refs": ["ev-2"]},
        "knowledge_status": {"status": "empty"},
    }
    report = build_decision_brief(
        incident={"id": "i-1", "service": "nginx", "status": "escalated"},
        operator_summary={
            "execution_status": "failed", "verification_status": "failed",
            "execution": {"error": "connection_timeout", "approval_id": "ap-1"},
            "verification": state["verification_result"],
            "approval": {"status": "consumed", "approver": "sre-operator"},
        },
        checkpoint={"state": state}, durable_evidence=[],
        findings=[], audit_events=[], now=NOW,
    )
    assert report["execution_outcome"]["status"] == "failed"
    assert report["verification_result"]["confidence"] == 0.19
    assert report["verification_result"]["evidence_refs"] == ["ev-2"]
    assert report["approval_readiness"]["approver"] == "sre-operator"
    assert report["knowledge_learning_status"]["review_available"] is False


def test_retrieved_cognia_document_exposes_source_title_without_inventing_use():
    state = {
        "knowledge_status": {"status": "available"},
        "knowledge_results": [{"source_id": "src-1", "title": "nginx playbook",
                               "knowledge_id": "k-2", "relevance": 0.82}],
    }
    result = make_brief(state=state)
    doc = result["cognia_knowledge"]["items"][0]
    assert doc["title"] == "nginx playbook"
    assert doc["use_status"] == "not_verified"


def test_vm_mcp_uses_allowlisted_tool_facts_not_raw_logs():
    report = make_brief(evidence=[
        {"id": "ev-status", "source": "vm_mcp", "created_at": NOW.isoformat(),
         "raw_data": {"diagnostic": "service_status", "success": True,
                      "active_state": "inactive", "sub_state": "dead",
                      "secret": "do-not-emit"}},
        {"id": "ev-logs", "source": "vm_mcp", "created_at": NOW.isoformat(),
         "raw_data": {"diagnostic": "service_logs", "count": 23,
                      "entries": ["password private_value"], "access_mode": "ssh"}},
    ])
    summary = " ".join(item["finding"] or "" for item in report["mcp_evidence"])
    assert "active_state=inactive" in summary
    assert "count=23" in summary
    assert "private_value" not in str(report)
    assert "entries" not in summary


def test_monitoring_provider_failure_creates_missing_evidence_warning():
    report = make_brief(evidence=[
        {"id": "ev-1", "source": "elasticsearch", "created_at": NOW.isoformat(),
         "raw_data": {"status": "unavailable", "result_count": 0}},
    ])
    assert "monitoring_source_unavailable:elasticsearch" in report["missing_evidence"]
    assert report["incident_summary"]["valid_evidence_count"] == 0


def test_decision_brief_exposes_llm_unknown_guidance_without_action_authority():
    guidance = {
        "status": "suggested", "execution_authority": False,
        "counts_as_evidence": False, "config_validation_passed": False,
        "items": [{"topic": "config_validation_method", "subject": "gfpapi",
                   "explanation": "unknown adapter",
                   "validation_approach": "Find documented non-mutating config check",
                   "verified": False}],
    }
    brief = make_brief(state={"context": {"unknown_guidance": guidance}})
    assert brief["unknown_guidance"]["items"][0]["verified"] is False
    assert brief["unknown_guidance"]["config_validation_passed"] is False
    assert brief["source_policy"]["authorizes_execution"] is False


def test_elapsed_incident_duration_does_not_invalidate_approval_snapshot():
    """Approval preflight must accept the same material state minutes later."""
    incident = {
        "id": "i-approval", "service": "nginx",
        "started_at": (NOW - timedelta(minutes=12)).isoformat(),
        "status": "open", "severity": "high",
    }
    stable_approval = {
        "approval_id": "ap-123", "status": "pending",
        "binding_complete": True, "target": "10.248.16.82",
        "tool": "ssh_vm", "action": "start_service",
    }
    def report(at):
        return build_decision_brief(
            incident=incident, operator_summary={"approval": stable_approval},
            checkpoint={"state": {"approval": stable_approval}, "version": 7},
            durable_evidence=[], findings=[], audit_events=[],
            now=at,
        )

    first = report(NOW)
    later = report(NOW + timedelta(seconds=43))
    assert first["incident_summary"]["elapsed_seconds"] == 720
    assert later["incident_summary"]["elapsed_seconds"] == 763
    assert first["generated_at"] != later["generated_at"]
    assert first["snapshot_id"] == later["snapshot_id"]
    assert first["approval_readiness"] == later["approval_readiness"]


def test_approval_snapshot_still_invalidates_on_material_action_change():
    incident = {
        "id": "i-approval", "service": "nginx",
        "started_at": (NOW - timedelta(minutes=12)).isoformat(),
    }
    def report(action, at):
        approval = {"approval_id": "ap-123", "status": "pending",
                    "binding_complete": True, "action": action,
                    "target": "10.248.16.82"}
        return build_decision_brief(
            incident=incident, operator_summary={"approval": approval},
            checkpoint={"state": {"approval": approval}, "version": 7},
            durable_evidence=[], findings=[], audit_events=[], now=at,
        )

    first = report("start_service", NOW)
    changed = report("restart_service", NOW + timedelta(seconds=43))
    assert first["snapshot_id"] != changed["snapshot_id"]


def test_agent_audit_preserves_distinct_findings_hypotheses_and_evidence_coverage():
    state = {
        "analysis_results": [
            {
                "agent_name": "vm", "finding_type": "service_stopped",
                "statement": "VM evidence: nginx inactive, configuration valid",
                "status": "partial", "confidence": 0.93,
                "evidence_count": 30, "evidence_coverage": 0.71,
                "evidence_quality": 0.85,
                "findings": ["active_state=inactive", "valid=true"],
                "hypotheses": [{
                    "hypothesis": "A manual stop is possible but not proven",
                    "probability": 0.34, "evidence_ids": ["ev1"],
                    "conflicting_evidence_ids": [],
                    "falsification_checks": ["Read auditd events"],
                }],
                "recommended_checks": ["Read system journal"],
                "missing_evidence": ["auditd logs for systemctl commands"],
                "uncertainty_reason": "actor_unknown",
                "requires_human_review": True,
                "evidence_ids": ["ev1", "ev2"],
                "analysis_details": {"focus": ["systemd", "process"],
                                     "private_prompt": "MUST_NOT_DISPLAY"},
            },
            {
                "agent_name": "network", "finding_type": "network_check",
                "statement": "Network check: tcp port 8080 not listening",
                "status": "success", "confidence": 0.32,
                "findings": ["No listener on target port"],
                "evidence_ids": ["ev3"],
            },
        ],
    }
    report = make_brief(state=state)
    vm, network = report["agent_findings"]
    assert vm["findings"] == ["active_state=inactive", "valid=true"]
    assert network["findings"] == ["No listener on target port"]
    assert vm["evidence_coverage"] == 0.71
    assert vm["evidence_quality"] == 0.85
    assert vm["evidence_count"] == 30
    assert vm["hypotheses"][0]["probability"] == 0.34
    assert vm["hypotheses"][0]["evidence_refs"] == ["ev1"]
    assert vm["hypotheses"][0]["falsification_checks"] == ["Read auditd events"]
    assert vm["recommended_checks"] == ["Read system journal"]
    assert vm["requires_human_review"] is True
    assert vm["focus"] == ["systemd", "process"]
    assert "MUST_NOT_DISPLAY" not in str(report)
    assert report["source_policy"]["authorizes_execution"] is False


def test_agent_audit_is_backward_compatible_when_specialist_details_are_missing():
    report = make_brief(state={"analysis_results": [{
        "agent_name": "application",
        "statement": "unknown",
        "confidence": 0.12,
    }]})
    one = report["agent_findings"][0]
    assert one["findings"] == []
    assert one["hypotheses"] == []
    assert one["recommended_checks"] == []
    assert one["evidence_coverage"] is None
    assert one["evidence_count"] is None
