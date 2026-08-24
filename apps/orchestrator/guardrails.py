from typing import Any, Dict, List
from apps.evaluator import PlanEvaluator, EvaluationResult


class OrchestrationGuardrails:
    """Reusable evaluator gate for any orchestrator implementation."""

    @staticmethod
    def evaluate(plan: str, findings: List[Dict[str, Any]]) -> EvaluationResult:
        return PlanEvaluator.evaluate(plan, findings)

    @staticmethod
    def can_enter_decision(result: EvaluationResult) -> bool:
        return result.accepted
