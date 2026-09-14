from apps.orchestrator.e2e_graph import E2EOrchestrator
from integrations.cognia import CogniaAPIError, CogniaConfigurationError, CogniaContractError


def test_cognia_failure_statuses_are_not_collapsed_to_empty_results():
    unavailable = E2EOrchestrator._knowledge_failure_status(
        CogniaAPIError(503, "SEARCH_DEPENDENCY_UNAVAILABLE", trace_id="trace-1")
    )
    assert unavailable == {
        "provider": "cognia",
        "status": "unavailable",
        "code": "SEARCH_DEPENDENCY_UNAVAILABLE",
        "http_status": 503,
        "trace_id": "trace-1",
    }
    assert E2EOrchestrator._knowledge_failure_status(CogniaAPIError(403, "FORBIDDEN"))["status"] == "forbidden"
    assert E2EOrchestrator._knowledge_failure_status(CogniaAPIError(404, "KB_NOT_FOUND"))["status"] == "not_accessible"
    assert E2EOrchestrator._knowledge_failure_status(CogniaConfigurationError("missing"))["status"] == "misconfigured"
    assert E2EOrchestrator._knowledge_failure_status(CogniaContractError("shape"))["status"] == "invalid_contract"
