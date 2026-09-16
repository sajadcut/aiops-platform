import json

import pytest

from agents.recovery import RecoveryAgent
from agents.recovery.engine import build_recovery_readiness_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def log(eid, message, **raw):
    return {"id": eid, "type": "log", "source": raw.pop("source", "backup"), "message": message, "raw_data": raw}


def metric(eid, name, value, **raw):
    return {"id": eid, "type": "metric", "source": raw.pop("source", "prometheus"), "name": name, "value": value, "raw_data": raw}


def analyze(evidence, **context):
    return build_recovery_readiness_analysis(evidence, service_name="orders-db", context=context)


def test_backup_success_but_restore_untested_caps_recoverability_confidence():
    result = analyze([
        log("backup", "backup succeeded", backup_time="2026-09-16T09:00:00Z", status="success", expected_schedule_seconds=3600),
    ], incident_start="2026-09-16T10:00:00Z", rpo_seconds=3600)
    assert result["latest_backup"]["timestamp"] == "2026-09-16T09:00:00+00:00"
    assert result["latest_verified_restore_point"] is None
    assert result["restore_validation_status"] == "untested"
    assert result["confidence_ceiling"] <= 0.55
    assert "verified usable restore point" in result["coverage_gaps"]


def test_stale_backup_detects_missed_schedule_and_rpo_not_demonstrated():
    result = analyze([
        log("backup", "backup succeeded", backup_time="2026-09-16T06:00:00Z", status="success", expected_schedule_seconds=3600),
    ], incident_start="2026-09-16T10:00:00Z", rpo_seconds=3600)
    assert result["backup_freshness"]["freshness"] == "stale"
    assert result["backup_freshness"]["missed_backups_estimate"] >= 2
    assert result["rpo_status"] == "not_demonstrated"


def test_broken_replication_is_separate_recovery_risk():
    result = analyze([
        log("backup", "backup succeeded and integrity verified", backup_time="2026-09-16T09:00:00Z", status="success", verified=True),
        metric("repl", "replication_lag_seconds", 120, replication_state="failed", replication_healthy=False),
    ], incident_start="2026-09-16T10:00:00Z")
    assert result["replication"]["healthy"] is False
    assert "healthy replication" in result["coverage_gaps"]
    assert any(row["risk"] == "broken_replication" for row in result["risk_signals"])


def test_partial_kubernetes_velero_backup_exposes_pv_gap():
    result = analyze([
        log(
            "velero",
            "Velero backup partially failed",
            provider="velero",
            phase="PartiallyFailed",
            failed_items=2,
            pv_expected=5,
            pv_backed_up=3,
            backup_time="2026-09-16T09:00:00Z",
        )
    ], incident_start="2026-09-16T10:00:00Z")
    assert result["kubernetes_velero"]["partial_backups"]
    assert result["kubernetes_velero"]["partial_backups"][0]["pv_coverage"] == pytest.approx(0.6)
    assert "complete Kubernetes/PV snapshot coverage" in result["coverage_gaps"]


def test_healthy_dr_has_verified_point_rpo_and_rto_readiness():
    evidence = [
        log(
            "backup",
            "backup succeeded and integrity verified",
            backup_time="2026-09-16T09:30:00Z",
            status="success",
            verified=True,
            expected_schedule_seconds=3600,
            offsite=True,
            immutable=True,
        ),
        log(
            "restore",
            "restore test succeeded",
            restore_point_time="2026-09-16T09:30:00Z",
            restore_test_time="2026-09-16T09:45:00Z",
            restore_status="success",
            restore_duration_seconds=900,
        ),
        log(
            "replication",
            "replication streaming with WAL continuity",
            replication_state="streaming",
            replication_healthy=True,
            wal_continuity=True,
            lag_seconds=2,
        ),
        log("encryption", "encrypted backup key metadata available", encrypted=True, key_available=True),
    ]
    result = analyze(evidence, incident_start="2026-09-16T10:00:00Z", rpo_seconds=3600, rto_seconds=1800)
    assert result["latest_verified_restore_point"]["timestamp"] == "2026-09-16T09:30:00+00:00"
    assert result["potential_data_loss_window_seconds"] == 1800
    assert result["rpo_status"] == "compliant"
    assert result["rto_risk"] == "low"
    assert result["restore_validation_status"] == "verified"


def test_missing_encryption_key_evidence_is_explicit_gap_without_key_material():
    result = analyze([
        log(
            "backup",
            "backup succeeded encrypted copy",
            backup_time="2026-09-16T09:00:00Z",
            status="success",
            encrypted=True,
        )
    ], incident_start="2026-09-16T10:00:00Z")
    assert result["encryption"]["encrypted"] is True
    assert result["encryption"]["key_available"] is None
    assert result["encryption"]["metadata_only"] is True
    assert "encryption-key availability metadata" in result["coverage_gaps"]


class CapturingRecoveryLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "recovery-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        return LLMResponse(content=json.dumps({
            "severity": "high",
            "health_status": "degraded",
            "findings": ["backup exists but restore usability is not proven"],
            "affected_components": ["orders-db"],
            "probable_dependencies": ["storage"],
            "blast_radius": "orders",
            "hypotheses": [{
                "hypothesis": "recoverability is not demonstrated",
                "probability": 0.95,
                "evidence_ids": ["backup"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["run an approved restore test in an isolated environment"],
                "impacted_components": ["orders-db"],
                "recommended_next_evidence": ["restore test history"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["database"],
            "immediate_checks": ["inspect restore test history"],
            "confidence": 0.95,
        }), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_recovery_agent_runs_readiness_analyzer_before_llm_and_never_executes_restore():
    adapter = CapturingRecoveryLLM()
    incident = AgentInput(
        incident_id="rec-dod",
        service_name="orders-db",
        evidence_summary="backup succeeded",
        context={
            "incident_start": "2026-09-16T10:00:00Z",
            "evidence": [
                {"id": "backup", "type": "log", "source": "backup", "message": "backup succeeded", "raw_data": {"backup_time": "2026-09-16T09:00:00Z", "status": "success"}},
            ],
        },
    )
    output = await RecoveryAgent(adapter).analyze(incident)
    assert "RECOVERY_READINESS_ANALYSIS=" in adapter.prompt
    assert output.analysis_details["human_decision_required"] is True
    assert output.analysis_details["execution_boundary"] == "analysis_only_no_restore_or_failover"
    assert output.analysis_details["recovery_sequence"] == ["storage", "database", "core_dependency", "application"]
    assert output.confidence <= output.analysis_details["confidence_ceiling"]
    assert all(action.read_only for action in output.recommended_actions)
