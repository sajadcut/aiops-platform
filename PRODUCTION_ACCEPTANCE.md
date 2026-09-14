# Production Acceptance

Baseline: `MASTER.md 2.3 - Benchmark-driven Production Hardening`

Repository HEAD assessed: `a0d9da2f4923d2f3ea264a1010babebe576e2e6d`

Assessment date: 2026-09-14

The project may be called **100% production-ready only when every item below passes**. A green source or container CI suite alone is not enough; items that require the target restricted network, enterprise identity, production-like stateful infrastructure or real remediation targets must have recorded environment evidence.

| # | Scenario | Status | Pass condition / current evidence or blocker |
|---|---|---|---|
| 1 | Cold start | PARTIAL | Production validation is fail-closed in code, including authentication, MCP TLS/identity, migrations, pgvector and unsafe direct-control-plane access. A clean production-like staging cold start with real dependencies is still required. |
| 2 | Auth/RBAC | PARTIAL | API-key/OIDC/RBAC tests exist and protected routes declare explicit permissions, but exhaustive route-by-route authorization against the enterprise IdP and production role mapping is not yet accepted. |
| 3 | Secrets | PARTIAL | Repository/history/config hygiene and log redaction are CI-checked; external secret-store integration, issuance and rotation still require the real environment. |
| 4 | Database | PASS | CI proves empty DB and existing DB migration to head, pgvector/schema/governance persistence, PostgreSQL locking, downgrade and clean rebuild. |
| 5 | Approval | PASS | Durable bound approval, expiry/state transitions and atomic single-use consume are covered by code/tests and PostgreSQL acceptance. |
| 6 | Execution boundary | PASS | `ExecutionService` does not authorize writes from caller-provided `approval_granted`. Governed writes require durable approval where applicable plus a short-lived signed execution capability bound to incident, approval, tool, action, target, parameters, timeout, runbook and rollback intent. |
| 7 | MCP | PARTIAL | MCP is the canonical Control-Plane external-tool boundary. Provider adapters, TLS/auth/timeout controls, read/write identity separation and no automatic unsafe-write retry behavior are implemented; real Zabbix, Elastic Agent Builder, Prometheus, Kubernetes and VM MCP deployments still require controlled acceptance. |
| 8 | VM/Kubernetes write | REAL ENV REQUIRED | Real mutation must succeed only through allowlisted MCP capabilities, distinct write identity and cryptographically bound execution capability, then be independently verified. Arbitrary targets/actions and replayed capabilities must fail in staging. |
| 9 | Incident E2E | PARTIAL | Signal/Evidence/RCA/decision/approval/execution/verification components are repository-tested; representative real incidents with real MCP endpoints and remediation targets are not yet accepted end-to-end. |
| 10 | Failure E2E | PARTIAL | Durable runtime tests prove failed execution skips successful resolution and failed verification escalates. Real MCP/DB/LLM outage and recovery drills remain. |
| 11 | Observability | PARTIAL | Structured/redacted logging, correlation fields, metrics, health and readiness exist; centralized durable collection, alerting and full GenAI/agent/tool tracing are not production-accepted. |
| 12 | Deployment / supply chain | PARTIAL | Repository container acceptance is PASS: multi-stage runtime isolation, no `/opt/wheels` or `/build` in final rootfs, non-root runtime, smoke test, Trivy HIGH/CRITICAL gate, CycloneDX SBOM, cosign sign/verify path and immutable Kubernetes digest rendering all pass on the assessed HEAD. Real approved wheelhouse/base mirroring, OCI registry signing/verification, promotion policy and cluster deployment remain external acceptance items. |
| 13 | Resilience | PARTIAL | Retry/idempotency/rate-limit/pool and approval primitives exist, but multi-replica distributed rate limiting, restart/resume/failover semantics, production-like concurrency, load/soak and dependency-outage tests are incomplete. |
| 14 | Rollback | REAL ENV REQUIRED | Application, remediation and database rollback procedures must be exercised against production-like data/workloads with recorded recovery evidence. |
| 15 | Real staging gate | NOT TESTED | Full production-like deployment must pass smoke, incident, controlled write, independent verification, rollback, dependency-failure and recovery tests before promotion. |

## Mandatory pass conditions

1. Production config cold-starts cleanly and unsafe/missing config fails fast.
2. Unauthenticated/unauthorized access fails on every protected route.
3. No credentials are present in code/history/log output and production secrets are externally managed and rotatable.
4. Empty and existing PostgreSQL databases migrate without data loss; pgvector and rollback/rebuild work.
5. High-risk action requires durable, bound, unexpired, single-use approval.
6. No Agent or internal caller can bypass policy/approval; write actions require governed execution capability, remain allowlisted and are auditable.
7. Required MCPs initialize/list/call correctly, enforce TLS/auth/timeouts, separate read/write authority and never automatically retry unsafe writes.
8. VM/Kubernetes real writes are constrained to controlled MCP capabilities and verified after execution.
9. Representative incidents pass Signal → Evidence → Agents/RCA → Decision → Approval → Execution → fresh Verification → Audit/Memory.
10. Execution/verification/dependency failures fail closed and never mark an unsuccessful remediation resolved.
11. Request/incident/approval/execution identifiers correlate across durable logs, metrics and readiness.
12. The built image is isolated from builder artifacts, runs non-root/read-only under Kubernetes, passes vulnerability scan and SBOM generation, has a verified signing path, and app + migration are promoted by the same immutable digest. Real registry signing/promotion must also be accepted in the target environment.
13. Concurrent approvals/executions, retries, restart/resume, rate limits, pool pressure and partial outages are safe.
14. Application and database rollback are tested on production-like data.
15. A full staging acceptance gate passes before production promotion.

## Repository evidence at this baseline

On the assessed `main` HEAD:

- `quality` source/security/unit/integration suite: PASS.
- PostgreSQL `database-acceptance`: PASS.
- `container-acceptance`: PASS through runtime isolation, smoke, exported-rootfs validation, Trivy, CycloneDX SBOM, cosign sign/verify, immutable Kubernetes rendering and evidence upload.

These results close the previous repository-level execution-boundary and mutable-container-gate findings. They do **not** close external staging, HA/DR, enterprise identity, real MCP endpoint, real registry promotion or real remediation acceptance.

## Current rule

The current verdict is **NOT 100% PRODUCTION READY**. Any `PARTIAL`, `FAIL`, `NOT TESTED`, or unexecuted `REAL ENV REQUIRED` item blocks that claim. Status may only be promoted when backed by automated repository acceptance evidence and, where infrastructure mutation or enterprise infrastructure is involved, recorded target-environment evidence.
