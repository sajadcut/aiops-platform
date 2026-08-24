import pytest

from apps.orchestrator.e2e_graph import E2EOrchestrator


class FakeEvidenceCollector:
    async def collect(self, service, since, until=None):
        return {
            "service": service,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
            "evidence": [
                {"type": "log", "source": "test", "reference": "test-1", "raw_data": {"message": "HTTP 500"}}
            ],
        }


@pytest.mark.asyncio
async def test_e2e_blocks_execution_without_explicit_request():
    orchestrator = E2EOrchestrator()
    orchestrator.evidence_collector = FakeEvidenceCollector()

    result = await orchestrator.run(
        {
            "incident_id": "incident-test",
            "service_name": "payments",
            "evidence_summary": "HTTP 500 spike",
            "context": {"summary": {"error_rate": 20}},
            "findings": [],
            "messages": [],
        }
    )

    assert result["current_node"] == "end"
    assert result.get("terminal_reason") is not None
    assert "execution" not in [m for m in result.get("messages", []) if m == "execution"]
