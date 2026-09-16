from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class MessagingAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="messaging",
        description="Messaging and queue reliability analysis: broker reachability, queue depth, consumer lag, retries, dead-letter pressure and publish/consume failures",
        focus=[
            "broker reachability, controller/leader and replication state",
            "queue depth trend and oldest-message age",
            "consumer lag level, growth rate and rebalance frequency",
            "publish, consume and acknowledgement errors/latency",
            "retry, redelivery and dead-letter growth",
            "Kafka under-replicated/offline partitions, ISR changes and hot partitions when evidenced",
            "producer surge versus slow/crashed consumer separation",
            "broker storage/network pressure versus downstream application failure",
        ],
        required_evidence_types=["metric", "log"],
        read_tools=["prometheus_query", "elasticsearch_logs", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "network", "infrastructure", "dependency", "storage"],
    )
