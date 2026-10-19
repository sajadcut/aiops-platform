"""Central DB incident log correlation must remain service- and evidence-bound."""
import json
from types import SimpleNamespace

import pytest

from apps.context_service.dependency_log_analysis import (
    _error_signatures, analyze_dependency_logs,
)


def _log(service, message, *, source="elasticsearch"):
    return {
        "type": "log", "source": source,
        "reference": f"log-{service or 'unscoped'}",
        "raw_data": {"service": service, "message": message},
    }


def test_only_explicit_matching_service_logs_can_support_database_rca():
    evidence = [
        _log("gfpapi", "Database connection pool exhausted"),
        _log("", "Database password authentication failed"),
        _log("GFP_Backend", "Database connection refused"),
        _log("GFP_Backend", "Redis connection refused"),
    ]
    signatures, diag = _error_signatures(evidence, "database", "GFP_Backend")
    codes = {row["error_signature"] for row in signatures}
    assert codes == {"connection_refused"}
    assert all(row["evidence_ref"] == "log-GFP_Backend" for row in signatures)
    assert diag["log_records_inspected"] == 4


class Model:
    def __init__(self, hypothesis):
        self.hypothesis = hypothesis
        self.messages = []
    async def generate_with_messages(self, messages, **kwargs):
        self.messages.append((messages, kwargs))
        return SimpleNamespace(content=json.dumps({
            "hypothesis": self.hypothesis,
            "analysis_fa": "خطای احراز هویت دیتابیس به عنوان علت احتمالی باید با لاگ معتبر بررسی شود.",
        }), finish_reason="stop")


@pytest.mark.asyncio
async def test_model_cannot_invent_auth_failure_from_tcp_only():
    model = Model("authentication")
    result = await analyze_dependency_logs(
        service="GFP_Backend", family="database", adapter=model,
        evidence=[],
        probe={"dependencies": [{
            "kind": "postgresql", "host": "db.internal", "port": 6543,
            "port_inferred": False, "tcp_reachable": False,
        }]},
    )
    raw = result["raw_data"]
    assert raw["matching_endpoint_count"] == 1
    assert raw["hypothesis"] == "unknown"
    assert raw["model_status"] == "llm_output_rejected"
    assert raw["root_cause_confirmed"] is False
    assert model.messages[0][1]["stage"] == "central_dependency_error_correlation"
    assert json.loads(model.messages[0][0][1]["content"])["alert_service"] == "GFP_Backend"


@pytest.mark.asyncio
async def test_model_auth_hypothesis_requires_explicit_matching_database_log():
    model = Model("authentication")
    result = await analyze_dependency_logs(
        service="GFP_Backend", family="database", adapter=model,
        evidence=[
            _log("gfpapi", "Database password authentication failed"),
            _log("GFP_Backend", "Database password authentication failed"),
        ],
        probe={"dependencies": []},
    )
    raw = result["raw_data"]
    assert raw["hypothesis"] == "authentication"
    assert raw["model_status"] == "llm_analyzed"
    assert raw["error_signatures"][0]["source"] == "elasticsearch"
    assert raw["error_signatures"][0]["count"] == 1
    assert "password" not in json.dumps(model.messages[0][0][1]["content"]).lower()
