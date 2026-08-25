from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class RecoveryAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="recovery",
        description="Backup and recovery readiness analysis: backup job health, restore-point freshness, replication protection, RPO/RTO risk and recovery evidence",
        focus=[
            "backup job failures",
            "restore point freshness",
            "replication protection",
            "RPO/RTO risk",
            "recovery dependency readiness",
            "restore validation evidence",
        ],
        required_evidence_types=["log", "metric"],
        read_tools=["elasticsearch_logs", "prometheus_query", "knowledge_search"],
        default_handoffs=["storage", "database", "infrastructure", "application"],
    )
