# Production Acceptance

The project may be called **100% production-ready only when every item below passes**. A green unit-test suite alone is not enough.

| # | Scenario | Status | Pass condition / current blocker |
|---|---|---|---|
| 1 | Cold start | PARTIAL | Production validation is fail-closed in code, but a real production configuration has not completed a clean staging cold start. |
| 2 | Auth/RBAC | PARTIAL | API-key/OIDC/RBAC tests exist, but exhaustive route-by-route authorization and real IdP integration are not yet proven. |
| 3 | Secrets | PARTIAL | Current tree, full Git history and log redaction are CI-checked; external secret-store contents/rotation still require the real environment. |
| 4 | Database | PASS | CI proves empty DB + existing DB migration to head, pgvector/schema/persistence, locking, downgrade and clean rebuild on PostgreSQL. |
| 5 | Approval | PASS | Durable bound approval, expiry/state transitions and single-use consume are covered by code/tests and PostgreSQL acceptance. |
| 6 | Execution boundary | FAIL | `ExecutionService` still trusts caller-provided `approval_granted` + `approval_id`; an internal caller can bypass durable approval validation. Architecture decision required. |
| 7 | MCP | PARTIAL | Protocol/TLS/auth/timeout/no-write-retry behavior is tested; real configured MCP providers are not staging-validated end-to-end. |
| 8 | VM/Kubernetes write | REAL ENV REQUIRED | Real mutation must succeed only through controlled MCP and reject arbitrary targets/actions in staging. VM edge also needs cryptographically bound execution authorization, not only a non-empty approval ID. |
| 9 | Incident E2E | PARTIAL | Routing/evidence/RCA/decision/approval/execution/verification components are tested; representative real write incidents are not yet proven end-to-end. |
| 10 | Failure E2E | PARTIAL | Durable runtime now proves failed execution skips verification and failed verification escalates instead of resolving; real MCP/DB/LLM outage drills remain. |
| 11 | Observability | PARTIAL | Structured/redacted logging, correlation fields, metrics and readiness exist; centralized durable log collection and production alerting are not proven. |
| 12 | Deployment | FAIL | Kubernetes hardening is tested and API/migration artifact refs must match, but manifests still use mutable `registry.internal/aiops-platform:2.2`; immutable digest build/scan/promotion is required. |
| 13 | Resilience | PARTIAL | Retry/idempotency/rate-limit/pool and approval primitives exist, but production-like concurrency, restart/resume and dependency-outage load tests are incomplete. |
| 14 | Rollback | REAL ENV REQUIRED | App and DB rollback procedures must be exercised against production-like data/workloads. |
| 15 | Real staging gate | NOT TESTED | Full production-like deployment must pass smoke, incident, write, verification, rollback and recovery tests before promotion. |

## Mandatory pass conditions

1. Production config cold-starts cleanly and unsafe/missing config fails fast.
2. Unauthenticated/unauthorized access fails on every protected route.
3. No credentials are present in code/history/log output and production secrets are externally managed/rotatable.
4. Empty and existing PostgreSQL databases migrate without data loss; pgvector and rollback/rebuild work.
5. High-risk action requires durable, bound, unexpired, single-use approval.
6. No Agent or internal caller can bypass policy/approval; write actions are allowlisted and auditable.
7. Required MCPs initialize/list/call correctly, enforce TLS/auth/timeouts, and never retry unsafe writes.
8. VM/Kubernetes real writes are constrained to controlled MCP capabilities and verified after execution.
9. Representative incidents pass Signal → Evidence → Agents/RCA → Decision → Approval → Execution → fresh Verification → Audit.
10. Execution/verification/dependency failures fail closed and never mark an unsuccessful remediation resolved.
11. Request/incident/approval/execution identifiers correlate across durable logs, metrics and readiness.
12. The built image runs non-root/read-only, is vulnerability-scanned/signed, and app + migration are promoted by the same immutable digest.
13. Concurrent approvals/executions, retries, restart/resume, rate limits, pool pressure and partial outages are safe.
14. Application and database rollback are tested on production-like data.
15. A full staging acceptance gate passes before production promotion.

## Current rule

The current verdict is **NOT 100% PRODUCTION READY**. Any `PARTIAL`, `FAIL`, `NOT TESTED`, or unexecuted `REAL ENV REQUIRED` item blocks that claim. Status may only be promoted when backed by automated acceptance evidence and, where infrastructure mutation is involved, recorded staging evidence.
