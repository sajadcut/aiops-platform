# Project State — AI Ops NeoBankingOperation Platform

**Authority:** `MASTER.md` remains the Single Source of Truth. This file is an implementation-status companion and must not override architectural decisions in MASTER.

**Assessment date:** 2026-09-14

## Executive status

The repository is substantially implemented and CI-tested, but it is not yet fully production-accepted for a bank/enterprise environment. Cognia is now the canonical Governed Knowledge RAG; Operational Memory remains PostgreSQL + pgvector. External acceptance is still required for the real Cognia environment, MCP-backed observability/remediation, enterprise identity, PostgreSQL HA/DR, signed offline promotion and sustained load/failure behavior.

This file intentionally avoids a synthetic readiness percentage. Repository implementation evidence and real-environment acceptance are tracked separately.

## Implemented and strong

- Python + LangGraph governed workflow.
- PostgreSQL persistence with pgvector and migration acceptance in CI.
- Cognia provider boundary for Governed Knowledge RAG with Application Client machine authentication, opaque-token lifecycle, explicit KB selection, Search chunk traceability, authoring/revision contracts, optional Context Generation and no hidden local fallback.
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

## Canonical Knowledge boundary — Cognia

Cognia is the canonical Production RAG for governed organizational knowledge. The AIOps runtime is a Cognia consumer; it does not reimplement Cognia KB permissions, Revision lifecycle or activation state locally.

Repository contract now enforces these rules:

- Backend integration uses Cognia Client Application machine identity, not a human username/password.
- `clientId/clientSecret` are authentication credentials; numeric `clientApplicationId` is the Scope identity and is configured separately.
- Machine access tokens are opaque and are never decoded as JWTs; after expiry the client re-authenticates because the machine flow has no refresh token.
- Search sends explicit configured Knowledge Base IDs. Authorization is all-or-nothing and unauthorized KBs are not silently removed.
- Search consumes Current Active Revision chunks and preserves KB/Knowledge/Revision/Chunk traceability. `relevanceScore` is retrieval relevance only, not factual confidence.
- External Subject is accepted only from an explicit stable upstream contract. AIOps does not infer Subject identity from a service/customer display name and rejects Client Application scope spoofing.
- Cognia dependency/index/auth/permission failures remain typed provider states and are never converted to a successful empty result or hidden local-pgvector fallback.
- Knowledge registration supports Cognia idempotency semantics; automatic transient retry is only permitted when an `Idempotency-Key` is present.
- Candidate Revision uses `expectedCurrentCandidateRevisionId`; concurrency conflicts require a fresh read/decision and are not blindly retried.
- Machine integration does not perform human Approve/Reject decisions.
- Context Generation is optional until a Context Profile is provisioned. A Context Package is auxiliary input rather than an LLM answer, and `isSufficient=false` remains explicit.

The local `knowledge_documents`/pgvector model remains for migration compatibility and deterministic development/test fixtures. It is **not** the Production Governed Knowledge system of record.

## Canonical MCP external-tool boundary

MCP remains the mandatory Control-Plane transport for external **operational tools** such as observability and remediation systems. Cognia is a separate governed Knowledge API boundary and is not an operational MCP tool.

ContextBuilder uses MCP clients for Zabbix, Elastic Agent Builder, Prometheus and optional Kubernetes/VM Edge integrations. Native connectors are not the canonical Control-Plane Production path.

### Elastic Agent Builder MCP

Elastic integration uses Elastic Agent Builder MCP rather than the deprecated standalone Elastic MCP provider.

- Minimum supported Elastic Stack: **9.2**.
- Recommended Production baseline: **9.3+**, pinned to an approved patched release.
- Canonical endpoint: Kibana `/api/agent_builder/mcp` or Space-aware `/s/{space}/api/agent_builder/mcp`.
- `platform.core` is mandatory in the configured MCP namespaces.
- Log Evidence uses only the deterministic read-only ES|QL path.

## Partial / not production-accepted

### Cognia real environment

Repository behavior is implemented and tested, but strict Production acceptance requires the real approved Cognia environment. Required evidence includes HTTPS/TLS, Client Application credential issuance/rotation, exact KB grants, positive and negative authorization, Scope isolation, registration → Processing/Approval when applicable → `Activated` → Search, Search dependency/index outage with no fallback, and Context Profile/sufficiency behavior if Context Generation is enabled.

The supplied sandpod documentation currently names an HTTP endpoint. That endpoint is suitable only for controlled non-Production acceptance; Production startup requires an approved HTTPS Cognia URL with TLS verification enabled.

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

## Phase assessment against MASTER 2.4

| Phase | Current evidence |
|---|---|
| Phase 0 — Foundation & Contracts | Repository implementation strong; external governance controls remain |
| Phase 1 — Observability & Context | MCP-backed source contracts implemented; real endpoints pending |
| Phase 2 — LangGraph Intelligence | Triage/specialists/RCA/Evaluator implemented; production-quality/scale acceptance pending |
| Phase 3 — RAG & Operational Memory | Cognia canonical RAG contract + PostgreSQL/pgvector Memory implemented; real Cognia acceptance pending |
| Phase 4 — Controlled Automation | Policy/approval/execution strong; real target and adapter breadth pending |
| Phase 5 — Verification & Learning | Fresh verification and governed Memory exist; per-action objectives pending |
| Phase 6 — Production Hardening | CI/container/security controls strong; HA/DR/identity/OTel/external acceptance pending |
| Phase 7 — Scale & Advanced Agents | Broad agent set exists; Edge breadth and scale proof remain incomplete |

## Known architectural rules

1. Live Production Evidence is authoritative for the current Incident.
2. Cognia Governed Knowledge and Operational Memory are auxiliary, separate domains.
3. Cognia is the canonical Production Knowledge RAG; local pgvector Knowledge is not a Production fallback.
4. Agent/LLM output cannot authorize a write.
5. Asset identity, event idempotency and Incident correlation are deterministic.
6. Every external operational tool connection from the Control Plane uses MCP.
7. Write actions go through Decision/Policy → Approval where required → Execution Service → governed MCP write → independent Verification.
8. Peer Agent findings are analysis context, not Evidence.
9. Connector/MCP/Cognia failure cannot be interpreted as zero findings.
10. Elastic Evidence uses Agent Builder MCP >=9.2; standalone Elastic MCP is forbidden.
11. Dashboard operational health must be derived from durable/live state; synthetic service topology, SLOs and fake fallback telemetry are forbidden.

## Next engineering priorities

1. Acceptance-test Cognia against the real non-Production endpoint with an Application Client, exact KB grants and representative knowledge/scope lifecycle; provision an HTTPS Production endpoint/route before promotion.
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

- Real Cognia HTTPS/Application Client/KB grant/Scope/Search/lifecycle acceptance and optional Context Profile acceptance.
- Real Elastic Agent Builder MCP, Zabbix MCP, Prometheus MCP and optional K8s/VM Edge MCP endpoints.
- Enterprise MCP identity/mTLS and server-side authorization.
- Real remediation targets with least privilege and rollback drills.
- Before → action → after recovery evidence.
- PostgreSQL HA/DR and load/chaos acceptance.
- Internal registry signing/verification/promotion.
- Security review/red-team of prompt injection, Cognia/RAG scope, MCP/tool abuse, identity, memory and supply chain.

## Verdict

The repository now has a clear separation of trust boundaries: **Cognia is the canonical Governed Knowledge RAG**, **MCP is the canonical external operational-tool boundary**, **PostgreSQL/pgvector is the Operational Memory semantic store**, and **Live Evidence is authoritative for current Incident truth**. Strict Production Ready status still depends on real Cognia/MCP endpoint acceptance, enterprise identity, HA/DR and production-like failure/scale evidence.
