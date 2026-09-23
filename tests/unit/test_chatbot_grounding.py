from datetime import datetime, timedelta, timezone

from apps.chatbot.grounding import (
    EvidenceRecord,
    JudgeDecision,
    infer_request_policy,
    missing_capability_message,
    resolve_context,
    validate_rules,
)


def evidence(action="service_status", minutes_old=0):
    return EvidenceRecord(
        evidence_id=f"ev-{action}",
        source="vm_mcp",
        tool="vm_service_status",
        action=action,
        target="10.100.6.199",
        observed_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_old),
        status="success",
        data={"healthy": False},
    )


def test_knowledge_question_does_not_require_live_evidence():
    policy = infer_request_policy("OOMKilled چیست؟")
    assert policy.kind == "knowledge"
    assert policy.requires_live_evidence is False


def test_live_vm_status_requires_evidence():
    policy = infer_request_policy("وضعیت nginx روی 10.100.6.199 چیه؟")
    assert policy.kind == "operational"
    assert policy.requires_live_evidence is True
    assert "vm.service.status.read" in policy.required_capabilities


def test_mount_followup_maps_to_disk_capability():
    policy = infer_request_policy("/app چقدر فضا داره؟")
    assert policy.requires_live_evidence is True
    assert "vm.disk.read" in policy.required_capabilities


def test_diagnostic_requires_corroborating_checks():
    policy = infer_request_policy("چرا nginx بالا نمیاد؟")
    assert policy.diagnostic is True
    first = validate_rules(policy, [evidence()], "nginx inactive است", max_age_seconds=300, min_confidence=0.70)
    assert first.valid is False
    assert first.needs_replan is True

    corroborated = validate_rules(
        policy,
        [evidence("service_status"), evidence("service_logs")],
        "nginx inactive است و لاگ سرویس خطای پیکربندی نشان می‌دهد.",
        max_age_seconds=300,
        min_confidence=0.70,
    )
    assert corroborated.valid is True


def test_stale_operational_evidence_is_rejected():
    policy = infer_request_policy("وضعیت nginx چیه؟")
    result = validate_rules(
        policy, [evidence(minutes_old=10)], "nginx فعال است",
        max_age_seconds=300, min_confidence=0.70,
    )
    assert result.valid is False
    assert "fresh" in result.missing_evidence[0]


def test_context_resolver_reuses_validated_tool_target_and_service():
    rows = [
        {"role": "user", "content": "وضعیت nginx روی 10.100.6.199 چیه؟", "metadata": {}},
        {
            "role": "tool",
            "content": "vm_service_status completed",
            "metadata": {
                "tool": "vm_service_status",
                "target": "10.100.6.199",
                "parameters": {"service": "nginx"},
            },
        },
        {"role": "user", "content": "/app چقدر فضا داره؟", "metadata": {}},
    ]
    context = resolve_context(rows)
    assert context.target == "10.100.6.199"
    assert context.service == "nginx"
    assert context.path == "/app"


def test_judge_parser_requires_structured_json():
    decision = JudgeDecision.parse(
        '{"valid":true,"question_answered":true,"evidence_sufficient":true,'
        '"claims_grounded":true,"hallucination_risk":"low","tool_usage_complete":true,'
        '"missing_capabilities":[],"missing_evidence":[],"contradictions":[],'
        '"unsupported_claims":[],"needs_replan":false,"needs_user_clarification":false,'
        '"rewrite_required":false,"confidence":0.94,"reason":"grounded"}'
    )
    assert decision.valid is True
    assert decision.confidence == 0.94


def test_missing_capability_response_is_truthful_in_persian():
    policy = infer_request_policy("/app چقدر فضا داره؟")
    text = missing_capability_message("/app چقدر فضا داره؟", policy)
    assert "حدس" in text
    assert "vm.disk.read" in text
