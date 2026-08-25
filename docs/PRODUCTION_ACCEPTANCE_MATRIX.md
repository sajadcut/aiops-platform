# Production Acceptance Matrix

Baseline: `MASTER.md 2.2`
Branch: `production-hardening`

## Repository-level acceptance

| Requirement | Status | Evidence / gap |
|---|---|---|
| Python + LangGraph core | PASS | E2E graph + durable runtime; full repository test suite passes on the latest green test job |
| Context + live Evidence | PASS | Context Builder and Zabbix/Elasticsearch/Prometheus/VM adapters; controlled connector tests |
| Specialized agents | PASS | Triage/Application/Infrastructure/Kubernetes/Security/VM agents |
| RCA + Evaluator gate | PASS | RCA followed by mandatory Evaluator gate |
| Decision / Policy | PASS | Decision Engine + execution policy tests |
| Approval persistence/lifecycle | PASS | PostgreSQL approval store + guarded workflow path; live target validation remains external |
| Audit persistence/redaction | PASS | Audit service + PostgreSQL store + redaction; live production transaction validation remains external |
| Execution boundary | PASS | Tool Registry, validation, approval gate and idempotency |
| Runbook governance/dry-run/rollback contracts | PASS | Registry, validator, executor and repository tests; real target execution remains external |
| Verification | PASS | Independent VerificationEngine + post-execution live evidence collection path |
| Operational Memory write-back | PASS | E2E write-back after non-inconclusive verification |
| Knowledge RAG contract | PASS | pgvector retrieval plus audited `source_id`/`version`/`relevance`/`retrieved_at` contract |
| PostgreSQL + pgvector migration lifecycle | PARTIAL | Dedicated CI acceptance job added; latest run must finish successfully before this row is promoted to PASS |
| OIDC/JWT/RBAC | PASS | Signed JWT/OIDC validation + permission guards; enterprise issuer remains external validation |
| Rate limiting / API guardrails | PASS | Permission guards + strict rate limiting |
| Health/liveness/readiness | PASS | Repository tests and endpoints |
| Dashboard / incident actions | PASS | PostgreSQL-backed dashboard and remediation action paths; populated production dataset validation remains external |
| Offline Docker/Kubernetes | PASS | Offline Docker/Kubernetes definitions present |
| Image attestation workflow | PASS | Attestation/signing workflow exists; real internal registry signing/promotion remains external |
| Repository hygiene | PASS | Hygiene automation and CI guard present |
| CI unit/integration/scenario tests | PASS | Latest completed test job is green |
| CI database acceptance | PARTIAL | Real pgvector container path is now part of CI; final run result pending |

## External validation required

1. Real enterprise Zabbix/Elasticsearch/Prometheus endpoint acceptance.
2. Real least-privilege VM SSH remediation and CPU recovery.
3. Real runbook execution, rollback and idempotency against controlled targets.
4. Real enterprise OIDC issuer/JWKS and role mapping.
5. Internal registry image signing, verification and promotion.
6. Offline production installation and recovery test in the target network.

## Verdict rule

Repository-level Production Ready is allowed only when all CI jobs are green and no repository-level blocker remains. Overall external Production Ready remains blocked until the explicitly listed target-environment validations have evidence.
