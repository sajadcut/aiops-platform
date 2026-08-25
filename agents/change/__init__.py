from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class ChangeAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="change",
        description="Change correlation analysis: deployments, releases, configuration drift and recent operational changes",
        focus=["recent deployments", "release correlation", "configuration drift", "change windows", "rollback candidate evidence", "dependency changes"],
        required_evidence_types=["log"],
        read_tools=["elasticsearch_logs", "knowledge_search"],
        default_handoffs=["application", "kubernetes", "database"],
    )
