from apps.evaluator import PlanEvaluator


def test_rejects_empty_plan():
    result = PlanEvaluator.evaluate("", [])
    assert not result.accepted
    assert "empty_plan" in result.issues


def test_accepts_evidence_backed_plan():
    findings = [{"confidence": 0.9, "evidence_ids": ["e1"]}]
    result = PlanEvaluator.evaluate("inspect service", findings)
    assert result.accepted
    assert result.evidence_coverage == 1.0
