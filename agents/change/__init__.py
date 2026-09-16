from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class ChangeAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="change",
        description="Change correlation analysis: deployments, releases, configuration drift and recent operational changes",
        focus=[
            "deployment/release/version/image-digest timeline",
            "configuration, feature-flag and dependency-version changes",
            "Jenkins/build/deploy and Kubernetes rollout evidence",
            "schema/migration and infrastructure changes",
            "before-versus-after error/latency/traffic/resource deltas",
            "affected-scope overlap and canary/stable comparison",
            "alternative explanations and conflicting evidence",
            "rollback-candidate evidence without direct rollback authority",
        ],
        required_evidence_types=["log"],
        read_tools=["elasticsearch_logs", "prometheus_query", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "kubernetes", "database", "dependency", "infrastructure"],
    )
