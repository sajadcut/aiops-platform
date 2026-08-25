from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class DependencyAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="dependency",
        description="Service dependency and topology analysis: upstream/downstream health, fan-out, cascading symptoms and service-map correlation",
        focus=[
            "upstream/downstream dependency health",
            "cascading failure symptoms",
            "fan-out amplification",
            "service-map and architecture correlation",
            "dependency latency/error propagation",
            "shared dependency blast radius",
        ],
        required_evidence_types=["metric", "log"],
        read_tools=["prometheus_query", "elasticsearch_logs", "knowledge_search"],
        default_handoffs=["application", "database", "network", "identity"],
    )
