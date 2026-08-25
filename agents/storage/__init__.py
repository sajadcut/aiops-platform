from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class StorageAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="storage",
        description="Storage reliability analysis: capacity, inode, latency, IOPS, filesystem and persistence pressure",
        focus=["capacity", "inode pressure", "I/O latency", "IOPS saturation", "filesystem errors", "persistent volume symptoms"],
        required_evidence_types=["metric"],
        read_tools=["prometheus_query", "zabbix_read", "vm_telemetry", "knowledge_search"],
        default_handoffs=["infrastructure", "database", "kubernetes"],
    )
