from apps.runbook_service.runtime_guard import RunbookRuntimeGuard


def test_approval_revocation_only_for_proven_stale_operational_intent():
    stale_reasons = {
        "service_no_longer_unhealthy",
        "service_state_conflict_or_recovered",
        "fresh_service_recovery_action_changed",
    }
    transient_reasons = {
        "fresh_service_status_missing",
        "fresh_service_status_inconclusive",
        "ambiguous_live_service_state",
        "configuration_status_missing",
        "configuration_validation_failed",
        "runtime_precondition_failed",
        "runbook_runtime_guard_not_implemented",
    }

    for reason in stale_reasons:
        assert RunbookRuntimeGuard.approval_should_be_revoked(
            {"safe_to_execute": False, "reason": reason}
        ) is True

    for reason in transient_reasons:
        assert RunbookRuntimeGuard.approval_should_be_revoked(
            {"safe_to_execute": False, "reason": reason}
        ) is False

    assert RunbookRuntimeGuard.approval_should_be_revoked(
        {"safe_to_execute": True, "reason": "fresh_execution_preconditions_satisfied"}
    ) is False
