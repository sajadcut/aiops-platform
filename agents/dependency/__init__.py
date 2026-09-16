from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class DependencyAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="dependency",
        description="Service dependency and topology analysis: upstream/downstream health, fan-out, cascading symptoms and service-map correlation",
        focus=[
            "directed caller-to-callee service topology",
            "first failing edge and earliest anomaly",
            "critical path and shared dependencies",
            "fan-out and retry amplification",
            "timeout and error propagation direction",
            "circuit-breaker and external-service symptoms",
            "database, messaging, identity and regional dependencies",
            "unknown or uninstrumented nodes without assuming absence",
            "incomplete trace fallback to metrics/logs/topology with higher uncertainty",
        ],
        required_evidence_types=["metric", "log"],
        read_tools=["prometheus_query", "elasticsearch_logs", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "database", "network", "identity", "messaging"],
    )
