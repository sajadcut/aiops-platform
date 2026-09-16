from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class NetworkAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="network",
        description="Network reliability analysis: latency, packet loss, reachability, DNS-path symptoms and service connectivity",
        focus=[
            "L2/L3 interface state, errors, drops, routes and gateway reachability",
            "L4 TCP connect, retransmission, reset, SYN and timeout symptoms",
            "DNS success, NXDOMAIN, SERVFAIL, timeout, latency and record/resolver mismatch",
            "TLS/L7 symptoms only when live evidence supports them",
            "bandwidth, packet rate, queue/drop and conntrack pressure",
            "source-to-destination path correlation instead of destination-only diagnosis",
            "listener/service versus routing/policy/network fault separation",
        ],
        required_evidence_types=["metric"],
        read_tools=["prometheus_query", "zabbix_read", "vm_telemetry", "knowledge_search"],
        default_handoffs=["infrastructure", "application", "identity", "dependency"],
    )
