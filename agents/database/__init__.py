from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class DatabaseAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="database",
        description="Database reliability analysis: connections, locks, latency, replication, storage and query pressure",
        focus=["connection exhaustion", "slow queries", "locks/deadlocks", "replication lag", "transaction failures", "database saturation"],
        required_evidence_types=["metric", "log"],
        read_tools=["prometheus_query", "elasticsearch_logs", "knowledge_search"],
        default_handoffs=["application", "storage", "infrastructure"],
    )
