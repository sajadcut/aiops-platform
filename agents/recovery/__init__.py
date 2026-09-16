from datetime import datetime, timezone
from typing import Any, Optional

from agents.shared.base import AgentInput, AgentOutput
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


def _parse_time(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


class RecoveryAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="recovery",
        description="Backup and recovery readiness analysis: backup job health, restore-point freshness, replication protection, RPO/RTO risk and recovery evidence",
        focus=[
            "latest successful backup versus latest verified usable restore point",
            "backup freshness, schedule misses, duration and size anomaly",
            "coverage, retention, snapshot and protected/offsite copy evidence",
            "replication health, lag and transaction-log continuity",
            "RPO compliance and potential data-loss window",
            "RTO readiness and dependency recovery order",
            "restore-test history, integrity and verification evidence",
            "Kubernetes/PV and database recovery coverage when evidenced",
            "encryption/key availability metadata without exposing key material",
        ],
        required_evidence_types=["log", "metric"],
        read_tools=["elasticsearch_logs", "prometheus_query", "zabbix_read", "knowledge_search"],
        default_handoffs=["storage", "database", "infrastructure", "application"],
    )

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        output = await super().analyze(input_data)
        details = dict(output.analysis_details or {})
        deterministic = details.get("deterministic_analysis") or {}
        recovery = deterministic.get("recovery_points") or {}

        latest_backup = recovery.get("latest_restore_or_backup")
        latest_verified = recovery.get("latest_verified_restore_point")
        incident_time = None
        context = input_data.context or {}
        summary = context.get("summary") if isinstance(context.get("summary"), dict) else {}
        for candidate in (
            context.get("incident_start"),
            context.get("incident_time"),
            summary.get("incident_start"),
            summary.get("incident_time"),
        ):
            incident_time = _parse_time(candidate)
            if incident_time:
                break

        verified_time = _parse_time(latest_verified)
        data_loss_seconds = None
        if incident_time and verified_time and incident_time >= verified_time:
            data_loss_seconds = int((incident_time - verified_time).total_seconds())

        restore_validation_status = (
            "verified_restore_point_available"
            if latest_verified
            else "restore_validation_missing" if recovery.get("restore_validation_missing")
            else "no_restore_point_evidence"
        )
        coverage_gaps = list(output.missing_evidence or [])
        if latest_backup and not latest_verified:
            coverage_gaps.append("verified usable restore point")
        coverage_gaps = sorted(set(coverage_gaps))

        details.update({
            "latest_backup": latest_backup,
            "latest_verified_restore_point": latest_verified,
            "potential_data_loss_window_seconds": data_loss_seconds,
            "restore_validation_status": restore_validation_status,
            "coverage_gaps": coverage_gaps,
            "recovery_sequence": ["storage", "database", "core_dependency", "application"],
            "human_decision_required": True,
            "execution_policy": "analysis_only; restore/failover require Evaluator -> Policy -> Approval -> Execution -> Verification",
        })
        output.analysis_details = details
        return output
