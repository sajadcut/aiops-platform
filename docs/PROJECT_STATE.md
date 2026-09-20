# Project State — AI Ops NeoBankingOperation Platform

**Authority:** `MASTER.md` remains the Single Source of Truth. This file is an implementation-status companion and must not override architectural decisions in MASTER.

**Assessment date:** 2026-09-14

## Executive status

The repository is substantially implemented and CI-tested, but it is not yet fully production-accepted for a bank/enterprise environment. Cognia is the only Governed Knowledge RAG in every environment; Operational Memory remains PostgreSQL + pgvector. External acceptance is still required for the real Cognia environment, MCP-backed observability/remediation, enterprise identity, PostgreSQL HA/DR, signed offline promotion and sustained load/failure behavior.

This file intentionally avoids a synthetic readiness percentage. Repository implementation evidence and real-environment acceptance are tracked separately.

## Implemented and strong

- Python + LangGraph governed workflow.
- PostgreSQL persistence with pgvector for Operational Memory and migration acceptance in CI.
- Cognia-only Governed Knowledge RAG boundary with Application Client machine authentication, opaque-token lifecycle, explicit KB selection, Search chunk traceability, authoring/revision contracts, optional Context Generation and no alternate-RAG fallback.
- No runtime Knowledge provider selector and no PostgreSQL/pgvector Knowledge retrieval path.
- Historical pre-Cognia Knowledge content is retained only as a non-RAG archive without embedding/retrieval capability.
- Operational Memory remains PostgreSQL + pgvector and is separate from Cognia Knowledge.
- Source-agnostic Signal Gateway and deterministic bounded cross-source correlation.
- Cross-source Evidence Collector with explicit `queried`, `unavailable`, `error` and `skipped` source observations.
- Deterministic Asset Identity/Context.
- Triage plus specialist agents with peer context, coordination, RCA and mandatory Evaluator gate.
- Decision/Policy/Approval/Execution separation; Agents remain analysis-only.
- Fresh pre-execution Evidence capture and independent before/after Verification.
- OIDC/RBAC, Audit, durable workflow checkpoints and hardened CI/deployment contracts.
- Repository-wide Python import/dependency integrity validation.
- Operator-grade AIOps Control Center backed by durable state rather than fabricated telemetry.

## Sole Knowledge RAG boundary — Cognia

Cognia is the only RAG for governed organizational knowledge in development, test and production. The AIOps runtime is a Cognia consumer; it does not reimplement Cognia KB permissions, Revision lifecycle or activation state locally, and it has no second Knowledge retriever to use as fallback.

Repository contract enforces these rules:

- Backend integration uses Cognia Client Application machine identity, not a human username/password.
- `clientId/clientSecret` are authentication credentials; numeric `clientApplicationId` is the Scope identity and is configured separately.
- Machine access tokens are opaque and are never decoded as JWTs; after expiry the client re-authenticates because the machine flow has no refresh token.
- Search sends explicit configured Knowledge Base IDs. Authorization is all-or-nothing and unauthorized KBs are not silently removed.
- Search consumes Current Active Revision chunks and preserves KB/Knowledge/Revision/Chunk traceability. `relevanceScore` is retrieval relevance only, not factual confidence.
- External Subject is accepted only from an explicit stable upstream contract. AIOps does not infer Subject identity from a service/customer display name and rejects Client Application scope spoofing.
- Cognia dependency/index/auth/permission failures remain typed states and are never converted to a successful empty result. No alternate RAG exists to mask a Cognia failure.
- Knowledge registration supports Cognia idempotency semantics; automatic transient retry is only permitted when an `Idempotency-Key` is present.
- Candidate Revision uses `expectedCurrentCandidateRevisionId`; concurrency conflicts require a fresh read/decision and are not blindly retried.
- Machine integration does not perform human Approve/Reject decisions.
- Context Generation is optional until a Context Profile is provisioned. A Context Package is auxiliary input rather than an LLM answer, and `isSufficient=false` remains explicit.

PostgreSQL/pgvector is not a Knowledge RAG. It serves Operational Memory only. The historical `legacy_knowledge_documents_archive` is migration/audit storage only and has no embedding/retrieval path.

## Canonical MCP external-tool boundary

MCP remains the mandatory Control-Plane transport for external **operational tools** such as observability and remediation systems. Cognia is a separate governed Knowledge API boundary and is not an operational MCP tool.

ContextBuilder uses MCP clients for Zabbix, Elastic Agent Builder, Prometheus and optional Kubernetes/VM Edge integrations. Native connectors are not the canonical Control-Plane Production path.

### Elastic Agent Builder MCP

Elastic integration uses Elastic Agent Builder MCP rather than the deprecated standalone Elastic MCP provider.

- Minimum supported Elastic Stack: **9.2**.
- Recommended Production baseline: **9.3+**, pinned to an approved patched release.
- Canonical endpoint: Kibana `/api/agent_builder/mcp` or Space-aware `/s/{space}/api/agent_builder/mcp`.
- Elastic-specific MCP initialize baseline: `2024-11-05`.
- `platform.core` is mandatory in the configured MCP namespaces.
- Elastic MCP authentication is provider-specific and never inherits the internal MCP bearer. The Kibana MCP API supports API key and HTTP Basic authentication; AIOps accepts either an explicit Authorization header or a dedicated Kibana username/password pair.
- Log Evidence uses only the deterministic read-only ES|QL path; the required allowlisted tool is verified by readiness.

## Partial / not production-accepted

### Cognia real environment

Repository behavior is implemented and tested, but strict Production acceptance requires the real approved Cognia environment. Required evidence includes the approved target HTTP/HTTP/HTTPS endpoint (and no server-certificate verification for HTTPS), Client Application credential issuance/rotation, exact KB grants, positive and negative authorization, Scope isolation, registration → Approval when applicable → Processing → `Activated` → Search, Search dependency/index outage with explicit degradation, and Context Profile/sufficiency behavior if Context Generation is enabled.

The supplied sandpod documentation names an HTTP endpoint, and AIOps supports that transport. Production may use the approved Cognia HTTP or HTTP/HTTPS endpoint for the target environment; when HTTPS is used, TLS verification remains mandatory.

### MCP servers and external integrations

Control-Plane MCP boundaries and provider adapters are implemented, but real Zabbix, Elastic Agent Builder, Prometheus, Kubernetes and VM MCP endpoints still require controlled acceptance in the target restricted network.

### Multi-source incident correlation

Deterministic bounded correlation is implemented and race-guarded for PostgreSQL. It still requires real corpus measurements for false-merge/false-split behavior and CMDB/service-catalog authority.

### Execution and verification coverage

VM execution is MCP-backed, but real Edge MCP Server acceptance and broader Kubernetes/Windows/Ansible/Jenkins/DB/network governed write coverage remain incomplete. Per-action verification objectives still need runtime acceptance.

### HA / scale

PostgreSQL HA, backup/restore/PITR/DR, distributed worker/queue semantics, distributed rate limiting, load/soak and chaos acceptance remain incomplete.

### Identity / service-to-service security

OIDC/RBAC exists at repository level. MCP supports provider-specific authorization and mTLS configuration, but short-lived workload identity issuance/rotation and organization PKI integration are not yet externally accepted.

### Supply chain / offline production

The repository container gate proves isolated multi-stage runtime construction, vulnerability scanning, SBOM, a signing verification path and immutable release rendering. Real internal wheelhouse/base-image mirroring and OCI registry signing/promotion remain external acceptance items.

## Phase assessment against MASTER 2.5

| Phase | Current evidence |
|---|---|
| Phase 0 — Foundation & Contracts | Repository implementation strong; external governance controls remain |
| Phase 1 — Observability & Context | MCP-backed source contracts implemented; real endpoints pending |
| Phase 2 — LangGraph Intelligence | Triage/specialists/RCA/Evaluator implemented; production-quality/scale acceptance pending |
| Phase 3 — RAG & Operational Memory | Cognia-only RAG contract + PostgreSQL/pgvector Operational Memory implemented; real Cognia acceptance pending |
| Phase 4 — Controlled Automation | Policy/approval/execution strong; real target and adapter breadth pending |
| Phase 5 — Verification & Learning | Fresh verification and governed Memory exist; per-action objectives pending |
| Phase 6 — Production Hardening | CI/container/security controls strong; HA/DR/identity/OTel/external acceptance pending |
| Phase 7 — Scale & Advanced Agents | Broad agent set exists; Edge breadth and scale proof remain incomplete |

## Known architectural rules

1. Live Production Evidence is authoritative for the current Incident.
2. Cognia Governed Knowledge and Operational Memory are auxiliary, separate domains.
3. Cognia is the only Knowledge RAG; PostgreSQL/pgvector is Operational Memory only and the historical pre-Cognia archive is not retrievable as RAG.
4. Agent/LLM output cannot authorize a write.
5. Asset identity, event idempotency and Incident correlation are deterministic.
6. Every external operational tool connection from the Control Plane uses MCP.
7. Write actions go through Decision/Policy → Approval where required → Execution Service → governed MCP write → independent Verification.
8. Peer Agent findings are analysis context, not Evidence.
9. Connector/MCP/Cognia failure cannot be interpreted as zero findings.
10. Elastic Evidence uses Agent Builder MCP >=9.2; standalone Elastic MCP is forbidden.
11. Dashboard operational health must be derived from durable/live state; synthetic service topology, SLOs and fake fallback telemetry are forbidden.

## Next engineering priorities

1. Acceptance-test Cognia against the real target HTTP/HTTP/HTTPS endpoint with an Application Client, exact KB grants and representative Knowledge/Scope lifecycle; do not validate server certificates when HTTPS is selected.
2. Deploy and acceptance-test Elastic Agent Builder, Zabbix and Prometheus MCP endpoints with pinned upstream versions.
3. Integrate enterprise workload identity/mTLS certificate issuance/rotation for MCP.
4. Complete constrained Windows and Kubernetes write capabilities behind Execution/Approval.
5. Bind per-runbook verification objectives to Execution receipts.
6. Add correlation corpus acceptance and CMDB/service catalog authority, including authoritative service dependencies.
7. Decide distributed queue/workers/backpressure after load evidence and add distributed rate limiting.
8. PostgreSQL HA + backup/restore/PITR/DR acceptance.
9. OpenTelemetry GenAI/Agent/MCP/tool tracing.
10. Signed immutable offline artifact promotion and repository governance enforcement.

## External acceptance required before strict Production Ready verdict

- Real Cognia HTTP/HTTP/HTTPS endpoint, Application Client/KB grant/Scope/Search/lifecycle acceptance and optional Context Profile acceptance.
- Real Elastic Agent Builder MCP, Zabbix MCP, Prometheus MCP and optional K8s/VM Edge MCP endpoints.
- Enterprise MCP identity/mTLS and server-side authorization.
- Real remediation targets with least privilege and rollback drills.
- Before → action → after recovery evidence.
- PostgreSQL HA/DR and load/chaos acceptance.
- Internal registry signing/verification/promotion.
- Security review/red-team of prompt injection, Cognia/RAG scope, MCP/tool abuse, identity, memory and supply chain.

## Verdict

The repository now has a clear separation of trust boundaries: **Cognia is the only Governed Knowledge RAG**, **MCP is the canonical external operational-tool boundary**, **PostgreSQL/pgvector is the Operational Memory semantic store**, and **Live Evidence is authoritative for current Incident truth**. Strict Production Ready status still depends on real Cognia/MCP endpoint acceptance, enterprise identity, HA/DR and production-like failure/scale evidence.
