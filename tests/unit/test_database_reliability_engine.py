import json

import pytest

from agents.database import DatabaseAgent
from agents.database.engine import build_database_reliability_analysis, database_prompt_evidence_projection
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def metric(eid, name, value, *, baseline=None, source="prometheus", **raw):
    payload = dict(raw)
    if baseline is not None:
        payload["baseline"] = baseline
    return {"id": eid, "type": "metric", "source": source, "name": name, "value": value, "timestamp": "2026-09-16T10:00:00Z", "raw_data": payload}


def db_evidence(eid, diagnostic, *, source="postgresql", evidence_type="telemetry", **raw):
    return {"id": eid, "type": evidence_type, "source": source, "timestamp": "2026-09-16T10:00:00Z", "raw_data": {"diagnostic": diagnostic, **raw}}


def analyze(evidence):
    return build_database_reliability_analysis(evidence, service_name="orders-db", context={"incident_start": "2026-09-16T09:59:00Z"})


def codes(result):
    return {row["code"] for row in result["cause_candidates"]}


def test_connection_exhaustion_and_pool_pressure_are_explicit_candidates():
    result = analyze([
        metric("conn", "postgres_active_connections_ratio", 0.99, baseline=0.55),
        metric("pool", "orders_db_pool_utilization", 1.0, baseline=0.5),
        metric("waiters", "orders_db_pool_waiters", 35, baseline=0),
        metric("reject", "postgres_rejected_connections", 12, baseline=0),
    ])
    connection = result["connection_analysis"]
    assert connection["state"] == "rejecting_connections"
    assert connection["connection_utilization"] == 0.99
    assert connection["pool_waiters"] == 35
    assert connection["rejected_connections"] == 12
    assert "connection_capacity_exhaustion" in codes(result)


def test_deadlock_and_lock_waits_are_distinguished():
    result = analyze([
        metric("deadlocks", "postgres_deadlocks", 4, baseline=0),
        metric("blocked", "postgres_lock_waits", 9, baseline=0),
        db_evidence("wait", "wait_event", wait_event_type="Lock", wait_event="transactionid", wait_count=9, duration_ms=2400),
    ])
    found = codes(result)
    assert "deadlock" in found
    assert "lock_contention" in found
    assert result["contention_analysis"]["top_waits"][0]["wait_event"] == "transactionid"


def test_slow_query_uses_normalized_fingerprint_and_historical_delta():
    raw_query = "SELECT * FROM orders WHERE status='ready' AND shard_id=42"
    result = analyze([db_evidence("query", "pg_stat_statements", evidence_type="query_stats", queryid="9911", query=raw_query, mean_exec_time_ms=1450, baseline_mean_exec_time_ms=110, calls=850, total_exec_time_ms=1232500)])
    top = result["query_analysis"]["top_query_fingerprints"][0]
    assert top["query_id"] == "9911"
    assert "ready" not in top["query_fingerprint"]
    assert "42" not in top["query_fingerprint"]
    assert "?" in top["query_fingerprint"]
    assert top["relative_latency_delta"] > 10
    assert "slow_query" in codes(result)
    assert result["biggest_temporal_deltas"][0]["kind"] == "query_fingerprint"


def test_replication_lag_is_a_separate_reliability_candidate():
    result = analyze([
        metric("lag", "postgres_replication_lag_seconds", 45, baseline=1, source="postgresql"),
        db_evidence("replica", "replication_status", role="standby", state="streaming", replication_lag_seconds=45),
    ])
    assert result["replication_analysis"]["degraded"] is True
    assert result["replication_analysis"]["lag_seconds"] == 45
    assert "replication_issue" in codes(result)
    assert "recovery" in result["handoff_candidates"]


def test_storage_induced_latency_handoffs_to_storage_not_automatic_database_root_cause():
    result = analyze([
        metric("db-lat", "postgres_query_latency_ms", 380, baseline=90),
        metric("storage", "db_storage_latency_ms", 85, baseline=4),
        metric("cpu", "database_cpu_utilization", 38, baseline=35),
    ])
    candidate = next(row for row in result["cause_candidates"] if row["code"] == "storage_induced_latency")
    assert candidate["handoff"] == "storage"
    assert candidate["root_cause_status"] == "candidate_requires_falsification"
    assert "storage" in result["handoff_candidates"]


def test_application_connection_storm_requires_connection_delta_plus_client_evidence():
    result = analyze([
        metric("connections", "postgres_connection_count", 180, baseline=50),
        metric("ratio", "postgres_connection_utilization", 0.9, baseline=0.25),
        db_evidence("client", "application_connection_storm", source="application", application_name="orders-api", source_component="orders-api", connection_rate=240),
    ])
    candidate = next(row for row in result["cause_candidates"] if row["code"] == "application_connection_storm")
    assert candidate["handoff"] == "application"
    assert "application" in result["handoff_candidates"]


def test_healthy_busy_database_is_not_mislabeled_as_fault():
    result = analyze([
        metric("ratio", "postgres_connection_utilization", 0.82, baseline=0.78),
        metric("qps", "postgres_queries_per_second", 5200, baseline=5000),
        metric("errors", "postgres_db_error_rate", 0, baseline=0),
        metric("latency", "postgres_query_latency_ms", 18, baseline=17),
        metric("cpu", "database_cpu_utilization", 64, baseline=60),
        metric("storage", "db_storage_latency_ms", 4, baseline=4),
    ])
    assert codes(result) == {"healthy_busy_database"}
    assert result["cause_candidates"][0]["root_cause_status"] == "candidate_requires_falsification"
    assert result["policy"].startswith("database alerts are symptoms")


def test_postgresql_adapter_surfaces_activity_vacuum_wal_and_restart_chronology():
    result = analyze([
        db_evidence("activity", "pg_stat_activity", state="active", wait_event_type="IO", wait_event="DataFileRead", application_name="orders-api", transaction_duration_ms=3400),
        db_evidence("vacuum", "autovacuum", relation="orders", n_dead_tup=850000, n_live_tup=1200000, autovacuum_age_seconds=5400),
        db_evidence("wal", "checkpoint_stats", wal_bytes_per_second=90000000, checkpoint_write_time_ms=4200, checkpoints_req=44, checkpoints_timed=3),
        db_evidence("restart", "failover", evidence_type="event", role="primary"),
    ])
    pg = result["postgresql"]
    assert pg["pg_stat_activity"][0]["application_name"] == "orders-api"
    assert pg["vacuum_autovacuum"][0]["dead_tuples"] == 850000
    assert pg["wal_checkpoint"][0]["checkpoints_requested"] == 44
    assert result["event_analysis"]["restart_failover_events"][0]["event"] == "failover"


def test_database_prompt_projection_redacts_sql_literals_and_bind_parameters():
    evidence = [{
        "id": "sql", "type": "query_stats", "source": "postgresql",
        "message": "SELECT * FROM jobs WHERE state='ready' AND shard_id=7788",
        "raw_data": {"diagnostic": "pg_stat_statements", "query": "SELECT * FROM jobs WHERE state='ready' AND shard_id=7788", "parameters": {"state": "ready", "shard_id": 7788}},
    }]
    encoded = json.dumps(database_prompt_evidence_projection(evidence))
    assert "state='ready'" not in encoded
    assert "7788" not in encoded
    assert "[REDACTED]" in encoded
    assert "query_fingerprint" in encoded


class CapturingDatabaseLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "database-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        payload = {
            "severity": "medium", "health_status": "degraded", "findings": ["query fingerprint latency increased versus baseline"],
            "affected_components": ["orders-db"], "probable_dependencies": [], "blast_radius": "orders-db",
            "hypotheses": [{"hypothesis": "a normalized query fingerprint regressed", "probability": 0.75, "evidence_ids": ["query"], "conflicting_evidence_ids": [], "falsification_checks": ["compare the same fingerprint before and during the incident"], "impacted_components": ["orders-db"], "recommended_next_evidence": ["execution plan for the normalized fingerprint"]}],
            "missing_evidence": [], "handoff_agents": [], "immediate_checks": ["Inspect normalized query statistics and wait events"], "confidence": 0.75,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_database_agent_computes_features_before_llm_and_never_prompts_raw_sql_literals():
    adapter = CapturingDatabaseLLM()
    incident = AgentInput(
        incident_id="inc-db-redaction", service_name="orders-db", evidence_summary="query latency regression",
        context={"evidence": [
            {"id": "query", "type": "query_stats", "source": "postgresql", "raw_data": {"diagnostic": "pg_stat_statements", "queryid": "9911", "query": "SELECT * FROM orders WHERE status='queued' AND shard_id=998877", "mean_exec_time_ms": 1100, "baseline_mean_exec_time_ms": 90, "calls": 500}},
            metric("metric", "postgres_db_error_rate", 0, baseline=0),
            {"id": "db-log", "type": "log", "source": "postgresql", "message": "ERROR: slow statement detected"},
        ]},
    )
    result = await DatabaseAgent(adapter).analyze(incident)
    assert "DATABASE_ANALYSIS=" in adapter.prompt
    assert "status='queued'" not in adapter.prompt
    assert "998877" not in adapter.prompt
    assert result.analysis_details["top_query_fingerprints"]
    assert result.analysis_details["biggest_temporal_deltas"]
    assert result.analysis_details["execution_boundary"] == "analysis_only"
    assert all(action.read_only for action in result.recommended_actions)
