from pathlib import Path


def test_legacy_workflow_orchestrator_is_only_a_governed_facade():
    source = Path("apps/orchestrator/graph.py").read_text(encoding="utf-8")
    assert "E2EOrchestrator" in source
    assert "MockLLMProvider" not in source
    assert "StateGraph(" not in source
    assert "confidence = 0.88" not in source


def test_agent_layer_has_no_hardcoded_legacy_a2a_endpoints():
    root = Path("agents")
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "http://localhost:8001" not in text, path
