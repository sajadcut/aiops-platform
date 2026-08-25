from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class IdentityAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="identity",
        description="Identity/IAM analysis: authentication, authorization, token, certificate and identity-provider dependencies",
        focus=["authentication failures", "authorization denials", "token validation", "OIDC/JWKS symptoms", "certificate/TLS identity", "role mapping"],
        required_evidence_types=["log"],
        read_tools=["elasticsearch_logs", "knowledge_search"],
        default_handoffs=["security", "application", "network"],
    )
