from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class MessagingAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="messaging",
        description="Messaging and queue reliability analysis: broker reachability, queue depth, consumer lag, retries, dead-letter pressure and publish/consume failures",
        focus=[
            "broker reachability",
            "queue depth and backlog",
            "consumer lag",
            "publish/consume failures",
            "retry storms",
            "dead-letter queue growth",
            "message throughput and latency",
        ],
        required_evidence_types=["metric", "log"],
        read_tools=["prometheus_query", "elasticsearch_logs", "knowledge_search"],
        default_handoffs=["application", "network", "infrastructure", "dependency"],
    )
