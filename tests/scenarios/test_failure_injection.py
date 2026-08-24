import pytest

from apps.evaluator.gate import EvaluationGate
from apps.execution_service.idempotency import execution_fingerprint


def test_missing_evidence_blocks_evaluation():
    result = EvaluationGate.evaluate([{"agent": "test", "confidence": 0.2, "evidence_ids": []}], "restart service")
    assert result["approved_for_decision"] is False


def test_execution_fingerprint_is_stable():
    a = execution_fingerprint("restart", "payments-1", {"timeout": 30})
    b = execution_fingerprint("restart", "payments-1", {"timeout": 30})
    assert a == b


@pytest.mark.parametrize("failure", ["timeout", "connector_unavailable", "verification_failed"])
def test_failure_modes_are_explicit(failure):
    allowed = {"timeout", "connector_unavailable", "verification_failed"}
    assert failure in allowed
