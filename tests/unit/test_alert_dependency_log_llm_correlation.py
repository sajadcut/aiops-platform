"""AIOps correlates only same-service DB log signatures with verified DB probes."""
import json
from types import SimpleNamespace

import pytest

from apps.context_service.dependency_log_analysis import analyze_dependency_logs
from apps.decision_brief import build_decision_brief
from datetime import datetime, timezone


class Model:
    def __init__(self, answer):
        self.answer = answer
        self.prompts = []
    async def generate_with_messages(self, messages, **kwargs):
        self.prompts.append((messages, kwargs))
        return SimpleNamespace(
            content=json.dumps(self.answer, ensure_ascii=False),
            finish_reason="stop",
        )


@pytest.mark.asyncio
async def test_database_log_correlation_ignores_other_services_and_redacts_connection_strings():
    model = Model({
        "hypothesis": "pool",
        "analysis_fa": "در لاگ برنامه نشانهٔ فرسودگی Connection Pool مشاهده شده، اما علت قطعی تأیید نشده است.",
    })
    evidence = [
        {"type": "log", "source": "elasticsearch", "reference": "elastic-1",
         "raw_data": {
            "service": "GFP_Backend",
            "message": "NpgsqlException: timeout while getting a connection from pool "
                       "Password=TOP_SECRET_NEVER_SEND",
         }},
        {"type": "log", "source": "elasticsearch", "reference": "other",
         "raw_data": {
            "service": "payments",
            "message": "PostgreSQL SqlException: authentication failed",
         }},
        {"type": "log", "source": "vm_mcp", "reference": "redis-1",
         "raw_data": {
            "service": "GFP_Backend", "entries": [
                "Redis SocketTimeoutException and password TOP_SECRET_NEVER_SEND",
            ],
         }},
    ]
    probe = {"dependencies": [
        {"kind": "postgresql", "host": "pg.internal", "port": 6543,
         "port_inferred": False, "tcp_reachable": True,
         "probe_status": "tcp_reachable"},
        {"kind": "redis", "host": "cache.internal", "port": 6389,
         "port_inferred": False, "tcp_reachable": False},
    ]}
    result = await analyze_dependency_logs(
        service="GFP_Backend", family="database",
        evidence=evidence, probe=probe, adapter=model)
    facts = result["raw_data"]
    assert facts["model_status"] == "llm_analyzed"
    assert facts["hypothesis"] == "pool"
    assert facts["matching_endpoint_count"] == 1
    assert facts["error_signatures"] == [{
        "source": "elasticsearch", "error_signature": "pool_exhaustion",
        "count": 1, "evidence_ref": "elastic-1",
    }]
    assert "TOP_SECRET_NEVER_SEND" not in str(result)
    assert "TOP_SECRET_NEVER_SEND" not in str(model.prompts)
    assert "cache.internal" not in str(model.prompts)
    assert model.prompts[0][1]["stage"] == "central_dependency_error_correlation"


@pytest.mark.asyncio
async def test_no_real_db_logs_and_no_db_endpoint_reports_unverified_without_llm():
    model = Model({
        "hypothesis": "network",
        "analysis_fa": "علت قطعاً شبکه است و اثبات شده است.",
    })
    result = await analyze_dependency_logs(
        service="GFP_Backend", family="database",
        evidence=[{"type": "log", "source": "vm_mcp",
                   "raw_data": {"service": "GFP_Backend", "entries": [
                       "Redis connection timeout",
                   ]}}],
        probe={"dependencies": [{"kind": "redis", "host": "cache", "port": 6379}]},
        adapter=model,
    )
    raw = result["raw_data"]
    assert raw["model_status"] == "not_required"
    assert raw["hypothesis"] == "unknown"
    assert raw["root_cause_confirmed"] is False
    assert "تأیید نیست" in raw["summary"] or "قابل تأیید نیست" in raw["summary"]
    assert not model.prompts


def test_central_llm_db_hypothesis_is_only_db_alert_evidence():
    model_fact = {
        "id": "central-db", "source": "aiops_analysis",
        "created_at": "2026-10-19T20:25:00Z",
        "raw_data": {
            "server": "aiops_llm", "diagnostic": "dependency_error_log_analysis",
            "service": "GFP_Backend", "family": "database",
            "model_status": "llm_analyzed", "hypothesis": "pool",
            "summary": "لاگ دیتابیس نشانه‌های خطای connection pool دارد.",
            "error_signatures": [{"error_signature": "pool_exhaustion", "count": 2}],
            "matching_endpoint_count": 1,
            "read_only": True, "root_cause_confirmed": False,
        },
    }
    for topic, expected in [
        ("GFP_Backend database connection errors", True),
        ("GFP_Backend Redis errors", False),
    ]:
        brief = build_decision_brief(
            incident={
                "id": "inc", "service": "GFP_Backend",
                "severity": "high", "status": "analyzing",
                "summary": topic, "context": {"source": "zabbix"},
            },
            operator_summary={"likely_cause": "unverified"},
            checkpoint={"state": {}, "version": 1},
            durable_evidence=[
                {"id": "trigger", "source": "zabbix",
                 "created_at": "2026-10-19T20:24:55Z",
                 "raw_data": {"service": "GFP_Backend", "name": topic,
                              "signal_type": topic, "event_value": "1"}},
                model_fact,
            ],
            findings=[], audit_events=[],
            now=datetime(2026, 10, 19, 20, 26, tzinfo=timezone.utc),
        )
        report = brief["alert_focused_report"]
        included = any(item["tool"] == "dependency_error_log_analysis"
                       for item in report["related_checks"])
        assert included is expected
        assert report["root_cause_confirmed"] is False
