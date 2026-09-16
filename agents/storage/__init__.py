from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class StorageAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="storage",
        description="Storage reliability analysis: capacity, inode, latency, IOPS, filesystem and persistence pressure",
        focus=[
            "capacity percentage and growth trend",
            "inode pressure",
            "IOPS, throughput, await/latency, queue depth and utilization",
            "device, filesystem, mount and read-only errors",
            "SMART/NVMe/SCSI indicators as probabilistic evidence, not certainty",
            "multipath and networked-storage symptoms",
            "persistent-volume attach/mount/throttling symptoms",
            "distributed-storage OSD/PG/degraded/slow-op evidence when available",
            "workload-driven pressure versus storage-originated failure",
        ],
        required_evidence_types=["metric"],
        read_tools=["prometheus_query", "zabbix_read", "vm_telemetry", "knowledge_search"],
        default_handoffs=["infrastructure", "database", "kubernetes", "recovery"],
    )
