import pytest

import apps.orchestrator.e2e_graph as e2e_module
from apps.orchestrator.e2e_graph import E2EOrchestrator


@pytest.mark.asyncio
async def test_orchestrator_evaluator_passes_authoritative_live_evidence_ids(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)
    captured = {}

    def fake_evaluate(findings, plan, coordination=None, live_evidence_ids=None):
        captured["findings"] = findings
        captured["plan"] = plan
        captured["live_evidence_ids"] = list(live_evidence_ids or [])
        return {
            "approved_for_decision": False,
            "confidence": 0.0,
            "evidence_count": 0,
            "evidence_coverage": 0.0,
            "agreement_score": 0.0,
            "missing_evidence": [],
            "disagreement": False,
            "contradictions": [],
            "specialist_failures": [],
            "degraded_specialist_analysis": False,
            "grounded_specialists": [],
            "operational_state_resolved": False,
            "deterministic_recovery_agents": [],
            "human_review_required": False,
            "unsafe_recommendations": [],
            "non_blocking_advisories": [],
            "blockers": ["synthetic"],
            "reason": "synthetic",
        }

    monkeypatch.setattr(e2e_module.EvaluationGate, "evaluate", fake_evaluate)
    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )

    state = {
        "findings": [{"agent_name": "vm", "evidence_ids": ["ev-ref"]}],
        "final_plan": "investigate",
        "coordination": {},
        "context": {
            "evidence": [
                {"evidence_id": "ev-id"},
                {"id": "ev-row-id"},
                {"reference": "ev-ref"},
                {"source_id": "ev-source"},
                {"reference": "ev-ref"},
            ]
        },
    }

    await orchestrator._evaluator_node(state)

    assert captured["live_evidence_ids"] == [
        "ev-id",
        "ev-row-id",
        "ev-ref",
        "ev-source",
    ]
