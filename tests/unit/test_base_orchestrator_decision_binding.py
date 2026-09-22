from types import SimpleNamespace

import pytest

import apps.orchestrator.e2e_graph as e2e_module
from apps.orchestrator.e2e_graph import E2EOrchestrator


def _finding(confidence: float = 0.95):
    return {
        "agent_name": "vm",
        "confidence": confidence,
        "evidence_ids": ["live-1", "live-2", "live-3"],
        "evidence_coverage": 1.0,
    }


@pytest.mark.asyncio
async def test_base_decision_rejects_unknown_execution_tool(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)
    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )
    monkeypatch.setattr(e2e_module.tool_registry, "get_tool", lambda _name: None)

    state = {
        "final_plan": "Check the service and recover it if required.",
        "findings": [_finding()],
        "execution_request": {
            "tool_name": "not_registered",
            "action": "start_service",
            "target": "vm01",
        },
        "context": {},
    }

    result = await orchestrator._decision_node(state)

    assert result["decision"]["action"] == "reject"
    assert result["decision"]["metadata"]["tool_exists"] is False


@pytest.mark.asyncio
async def test_base_decision_rejects_write_target_known_only_from_knowledge(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)
    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )
    tool = SimpleNamespace(risk_level="medium", requires_approval=True)
    monkeypatch.setattr(e2e_module.tool_registry, "get_tool", lambda _name: tool)

    state = {
        "final_plan": "Start the stopped service through the governed tool.",
        "findings": [_finding()],
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "vm01",
        },
        "context": {
            "topology_context": {
                "requires_live_verification": True,
            }
        },
    }

    result = await orchestrator._decision_node(state)

    assert result["decision"]["action"] == "reject"
    assert result["decision"]["metadata"]["target_identity_verified"] is False


@pytest.mark.asyncio
async def test_base_decision_forces_approval_for_registered_write_tool(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)
    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )
    tool = SimpleNamespace(risk_level="medium", requires_approval=True)
    monkeypatch.setattr(e2e_module.tool_registry, "get_tool", lambda _name: tool)

    state = {
        "final_plan": "Start the stopped service after policy approval.",
        "findings": [_finding()],
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "vm01",
        },
        "context": {},
    }

    result = await orchestrator._decision_node(state)

    assert result["decision"]["action"] == "require_approval"
    assert result["decision"]["requires_approval"] is True
    assert result["decision"]["metadata"]["tool_exists"] is True
    assert result["decision"]["metadata"]["execution_binding_complete"] is True
