from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


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
