from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class NetworkAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="network",
        description="Network reliability analysis: latency, packet loss, reachability, DNS path and service connectivity",
        focus=["latency", "packet loss", "reachability", "connection resets", "routing symptoms", "service connectivity"],
        required_evidence_types=["metric"],
        read_tools=["prometheus_query", "zabbix_read", "knowledge_search"],
        default_handoffs=["infrastructure", "dns", "application"],
    )
