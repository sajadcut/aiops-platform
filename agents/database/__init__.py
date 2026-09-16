from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class DatabaseAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="database",
        description="Database reliability analysis: connections, locks, latency, replication, storage and query pressure",
        focus=[
            "connection utilization, pool exhaustion and rejected connections",
            "normalized query latency/fingerprints and long-running transactions",
            "locks, deadlocks and wait-event contention",
            "replication health and lag",
            "WAL/checkpoint/vacuum pressure when vendor evidence supports it",
            "CPU/memory/cache saturation and storage latency contribution",
            "application connection storms versus database-local faults",
            "restart/failover and network/dependency symptoms",
        ],
        required_evidence_types=["metric", "log"],
        read_tools=["prometheus_query", "elasticsearch_logs", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "storage", "infrastructure", "recovery", "dependency", "network"],
    )
