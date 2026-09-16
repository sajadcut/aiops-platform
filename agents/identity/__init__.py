from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec


class IdentityAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="identity",
        description="Identity/IAM analysis: authentication, authorization, token, certificate and identity-provider dependencies",
        focus=[
            "authentication versus authorization failures and 401/403 separation",
            "OIDC discovery, issuer and audience validation",
            "JWKS reachability, rotation and missing signing keys",
            "token exp/nbf, signature algorithm and clock skew",
            "scope, role, group and RBAC mapping",
            "IdP latency/outage and DNS dependencies",
            "certificate expiry, renewal, trust-chain and TLS handshake symptoms",
            "mandatory credential/token/secret redaction",
        ],
        required_evidence_types=["log"],
        read_tools=["elasticsearch_logs", "prometheus_query", "zabbix_read", "knowledge_search"],
        default_handoffs=["security", "application", "network", "dependency"],
    )
