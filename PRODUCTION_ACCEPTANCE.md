# Production Acceptance

Baseline: `MASTER.md 2.4 - Cognia Governed Knowledge RAG`

Repository code baseline assessed: `64c69f194b9ca2bfc60c74b10fc6e2743742219e` on `feat/cognia-rag-integration`

Assessment date: 2026-09-14

The project may be called **100% production-ready only when every item below passes**. A green source or container CI suite alone is not enough; items that require the target restricted network, enterprise identity, production-like stateful infrastructure, Cognia grants or real remediation targets must have recorded environment evidence.

| # | Scenario | Status | Pass condition / current evidence or blocker |
|---|---|---|---|
| 1 | Cold start | PARTIAL | Production validation is fail-closed in code, including authentication, Cognia provider/HTTPS/TLS/credentials/KBs, MCP TLS/identity, migrations, pgvector and unsafe direct-control-plane access. A clean production-like staging cold start with real dependencies is still required. |
| 2 | Auth/RBAC | PARTIAL | API-key/OIDC/RBAC tests exist and protected routes declare explicit permissions, but exhaustive route-by-route authorization against the enterprise IdP and production role mapping is not yet accepted. |
| 3 | Secrets | PARTIAL | Repository/config hygiene and recursive redaction cover secret-like keys, including Cognia client secret values by key classification. External secret-store integration, Cognia Client Application credential issuance/rotation and enterprise secret lifecycle still require the real environment. |
| 4 | Database | PASS | CI proves empty DB and existing DB migration to head, pgvector/schema/governance persistence, PostgreSQL locking, downgrade and clean rebuild. pgvector is the Operational Memory vector layer; local Knowledge tables are retained for compatibility/dev-test rather than Production Cognia authority. |
| 5 | Approval | PASS | Durable bound approval, expiry/state transitions and atomic single-use consume are covered by code/tests and PostgreSQL acceptance. |
| 6 | Execution boundary | PASS | `ExecutionService` does not authorize writes from caller-provided `approval_granted`. Governed writes require durable approval where applicable plus a short-lived signed execution capability bound to the concrete execution intent. |
| 7 | MCP | PARTIAL | MCP is the canonical Control-Plane external **operational-tool** boundary. Provider adapters, TLS/auth/timeout controls, read/write identity separation and no automatic unsafe-write retry behavior are implemented; real Zabbix, Elastic Agent Builder, Prometheus, Kubernetes and VM MCP deployments still require controlled acceptance. Cognia is a separate Knowledge API boundary, not an MCP operational tool. |
| 8 | Cognia Governed Knowledge RAG | REAL ENV REQUIRED | Repository contract is implemented: machine Client Application auth, opaque token/no refresh assumption, separate numeric Client Application Scope identity, explicit KB list, Active-Revision Chunk traceability, no hidden local fallback, typed errors, authoring idempotency, Revision concurrency, no machine approval and Context sufficiency. PASS requires the real approved Cognia environment with HTTPS/TLS, credentials, grants, Scope/lifecycle/Search/outage and optional Context Profile evidence. |
| 9 | VM/Kubernetes write | REAL ENV REQUIRED | Real mutation must succeed only through allowlisted MCP capabilities, distinct write identity and cryptographically bound execution capability, then be independently verified. Arbitrary targets/actions and replayed capabilities must fail in staging. |
| 10 | Incident E2E | PARTIAL | Signal/Evidence/RCA/decision/approval/execution/verification components are repository-tested and Cognia degradation is distinct from empty Knowledge. Representative real incidents with real Cognia/MCP endpoints and remediation targets are not yet accepted end-to-end. |
| 11 | Failure E2E | PARTIAL | Durable runtime tests prove failed execution skips successful resolution and failed verification escalates. Cognia provider failures are typed and do not silently fall back. Real Cognia/MCP/DB/LLM outage and recovery drills remain. |
| 12 | Observability | PARTIAL | Structured/redacted logging, correlation fields, metrics, health and readiness exist; centralized durable collection, alerting and full GenAI/agent/tool tracing are not production-accepted. |
| 13 | Deployment / supply chain | PARTIAL | Repository container acceptance proves multi-stage runtime isolation, no `/opt/wheels` or `/build` in final rootfs, non-root runtime, smoke, Trivy HIGH/CRITICAL gate, CycloneDX SBOM, cosign sign/verify path and immutable Kubernetes rendering. Real approved wheelhouse/base mirroring, OCI registry signing/verification, promotion policy, cluster deployment and Cognia egress allowlisting remain external acceptance items. |
| 14 | Resilience | PARTIAL | Retry/idempotency/rate-limit/pool and approval primitives exist. Cognia read retries are bounded, registration retries only when Idempotency-Key makes replay safe, and Candidate Revision is not blindly retried. Multi-replica distributed rate limiting, restart/resume/failover semantics, production-like concurrency, load/soak and dependency-outage tests are incomplete. |
| 15 | Rollback | REAL ENV REQUIRED | Application, remediation and database rollback procedures must be exercised against production-like data/workloads with recorded recovery evidence. Cognia Knowledge lifecycle is governed by Cognia Revision/activation semantics rather than an AIOps local rollback substitute. |
| 16 | Real staging gate | NOT TESTED | Full production-like deployment must pass Cognia dependency checks, smoke, incident, controlled write, independent verification, rollback, dependency-failure and recovery tests before promotion. |

## Mandatory pass conditions

1. Production config cold-starts cleanly and unsafe/missing config fails fast, including mandatory Cognia provider/HTTPS/TLS/Client Application/KB configuration.
2. Unauthenticated/unauthorized access fails on every protected route.
3. No credentials are present in committed config/log output and production secrets are externally managed and rotatable, including Cognia `clientSecret`.
4. Empty and existing PostgreSQL databases migrate without data loss; pgvector and rollback/rebuild work for platform persistence/Operational Memory.
5. High-risk action requires durable, bound, unexpired, single-use approval.
6. No Agent or internal caller can bypass policy/approval; write actions require governed execution capability, remain allowlisted and are auditable.
7. Required MCPs initialize/list/call correctly, enforce TLS/auth/timeouts, separate read/write authority and never automatically retry unsafe writes.
8. Cognia machine auth, exact KB grants, General/ClientApplication/ExternalSubject behavior where used, registration/Revision/Processing/Activation/Search, authorization failures, index/dependency outage/no-fallback and Context sufficiency where enabled are proven on a real non-Production environment. Production uses an approved HTTPS Cognia route.
9. VM/Kubernetes real writes are constrained to controlled MCP capabilities and verified after execution.
10. Representative incidents pass Signal → live Evidence → Cognia/Memory auxiliary context → Agents/RCA → Decision → Approval → Execution → fresh Verification → Audit/Memory.
11. Execution/verification/Cognia/MCP/dependency failures fail or degrade explicitly and never become false zero-results or successful remediation.
12. Request/incident/approval/execution identifiers correlate across durable logs, metrics and readiness without leaking Cognia tokens/secrets.
13. The built image is isolated from builder artifacts, runs non-root/read-only under Kubernetes, passes vulnerability scan and SBOM generation, has a verified signing path, and app + migration are promoted by the same immutable digest. Real registry signing/promotion and approved Cognia network egress must also be accepted in the target environment.
14. Concurrent approvals/executions, retries, restart/resume, rate limits, pool pressure and partial outages are safe.
15. Application and database rollback are tested on production-like data.
16. A full staging acceptance gate passes before production promotion.

## Repository evidence at this baseline

On the assessed Cognia code baseline:

- source/security/unit/integration suite: PASS after Cognia scoped-client regression alignment.
- PostgreSQL `database-acceptance`: part of the required quality gate and must remain green on the final promoted HEAD.
- `container-acceptance`: must remain green on the final promoted HEAD through runtime isolation, smoke, exported-rootfs validation, Trivy, CycloneDX SBOM, cosign sign/verify and immutable Kubernetes rendering.
- Cognia unit/contract coverage includes opaque machine token caching/re-authentication, explicit Search request construction, problem+json error mapping, no hidden fallback, chunk traceability, authoring idempotency, Scope anti-spoof, Revision concurrency/no blind retry, machine approval boundary, Context `isSufficient` semantics and production configuration fail-closed behavior.

Repository tests prove the **consumer contract**, not the real Cognia grants/data/index/network. Target Cognia acceptance remains `REAL ENV REQUIRED`.

## Current rule

The current verdict is **NOT 100% PRODUCTION READY**. Any `PARTIAL`, `FAIL`, `NOT TESTED`, or unexecuted `REAL ENV REQUIRED` item blocks that claim. Status may only be promoted when backed by automated repository acceptance evidence and, where external state, identity, knowledge grants or infrastructure mutation are involved, recorded target-environment evidence.
