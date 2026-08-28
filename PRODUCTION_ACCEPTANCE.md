# Production Acceptance

The project may be called **100% production-ready only when every item below passes**. A green unit-test suite alone is not enough.

| # | Scenario | Pass condition |
|---|---|---|
| 1 | Cold start | Production config starts cleanly; missing/unsafe config fails fast. |
| 2 | Auth/RBAC | Unauthenticated/unauthorized calls fail; every protected route enforces the intended role. |
| 3 | Secrets | No secret exists in current tree or full Git history; logs redact credentials. |
| 4 | Database | Empty DB and existing DB both migrate to head without data loss; pgvector works; rollback/rebuild works. |
| 5 | Approval | High-risk action cannot execute without durable, bound, unexpired, single-use approval. |
| 6 | Execution boundary | No Agent/internal caller can bypass policy/approval; writes are allowlisted and auditable. |
| 7 | MCP | Required MCPs initialize, list/call expected tools, enforce TLS/auth, timeout safely, and never retry unsafe writes. |
| 8 | VM/Kubernetes write | Real staging mutation succeeds only through controlled MCP; arbitrary shell/target/action is rejected. |
| 9 | Incident E2E | Signal → routing → evidence → RCA → decision → approval → execution → fresh verification → audit passes for representative incident families. |
| 10 | Failure E2E | MCP/DB/LLM/verification failures degrade safely; failed remediation never marks an incident resolved. |
| 11 | Observability | Request/incident/approval/execution IDs correlate across logs; metrics/readiness expose real dependency failure. |
| 12 | Deployment | Built image runs non-root/read-only, is vulnerability-scanned and promoted by immutable digest; app and migration use the same digest. |
| 13 | Resilience | Concurrent approvals/executions, retries, restart/resume, rate limits, pool exhaustion and partial dependency outage are safe. |
| 14 | Rollback | Application and database rollback procedures are tested on production-like data. |
| 15 | Real staging gate | Full production-like deployment passes smoke, incident, write, verification and rollback tests before promotion. |

## Current rule

If any scenario is `PARTIAL`, `NOT TESTED`, or requires an unexecuted real-environment check, the platform must **not** claim 100% production readiness.
