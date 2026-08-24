# Implementation Status vs MASTER.md

Updated: 2026-08-25

This file is traceability evidence, not a replacement for `MASTER.md`. It distinguishes implemented code from capabilities that still require live environment validation.

## Final completion batch implemented in repository

- Durable PostgreSQL workflow checkpoints and resumable runtime are present.
- Incident, Finding and Evidence persistence are present in the lifecycle runtime.
- Primary E2E audit events have a PostgreSQL flush path.
- Approval API create/get/approve/reject uses PostgreSQL persistence.
- Mandatory Evaluator gate is present before Decision.
- Live EvidenceCollector is connected to the primary Context node.
- Governed RunbookExecutor now provides validation, dry-run, execution, rollback routing and idempotency fingerprint handling.
- PostgreSQL-backed Dashboard KPI API is present.
- pgvector validation now checks extension presence and vector embedding dimensions when configured.
- Production configuration includes OIDC, RBAC/API key, pgvector and offline registry settings.
- CI contains syntax/tests plus tracked-artifact hygiene checks.
- Offline immutable image attestation workflow and deterministic attestation generator are present.
- Master API surface integration test and Runbook executor tests are present.
- Tracked `.env` and obsolete `alembic (2).zip` were removed; `.env.example` was added.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/e2e_graph.py` + durable runtime | Integrated |
| Specialized agents | Triage/Application/Infrastructure/Kubernetes/Security/VM | Implemented |
| PostgreSQL persistence | SQLAlchemy + governance/workflow/incident migrations | Implemented; live transaction verification required |
| pgvector | vector model + runtime extension/type/dimension validation | Implemented; target database validation required |
| Knowledge RAG | service + retrieval metadata + API | Integrated foundation |
| Operational Memory | service + namespace + E2E write-back | Integrated foundation |
| Context Builder | IncidentContext + normalization + EvidenceCollector | Integrated |
| Evidence | Zabbix + Elasticsearch + Prometheus aggregation | Integrated foundation; live target validation required |
| Hypothesis/RCA | evidence-linked contract + E2E RCA | Integrated foundation |
| Evaluator | mandatory `EvaluationGate` before Decision | Integrated |
| Decision Engine | policy/risk boundary | Implemented |
| Approval | PostgreSQL store + durable lookup/resume + API | Integrated; live commit/resume verification required |
| Execution | Tool Registry + policy + idempotency | Integrated foundation |
| Verification | VerificationEngine + VerificationGate | Integrated foundation |
| Audit | API + redaction + PostgreSQL store + primary-path flush | Integrated; live transaction verification required |
| Runbooks | governance + 3 MVP runbooks + registry + dry-run + executor | Integrated foundation; real tool/rollback environment validation required |
| Security/RBAC | deny-by-default + RBAC + API key + OIDC claim validation | Implemented foundation; real issuer/JWKS validation required |
| Observability | connector/evidence layer | Integrated foundation; controlled-environment validation required |
| APIs | Master-aligned incident resources + execution/approval/runbook/audit + dashboard | Implemented foundation; endpoint E2E suite added |
| Tests | unit + integration + scenario + failure-injection + approval/audit/runbook/API contracts | Improved; live connector acceptance pending |
| Offline deployment | Docker/Kubernetes + immutable digest attestation workflow | Foundation implemented; internal registry signing/promotion execution required |
| Dashboard | PostgreSQL-backed incident/approval/audit/verification KPIs | Implemented foundation; live data validation required |
| Workflow resume | PostgreSQL checkpoint store + durable runtime | Implemented foundation; restart/resume integration test requires real DB |
| Repository hygiene | `.gitignore` + cleanup script + CI enforcement + tracked `.env`/zip cleanup | Improved; historical cache files still require repository-wide deletion |
| CI | syntax + unit/integration/scenario + hygiene gate | Workflow defined; green execution must be confirmed by GitHub Actions |

## Remaining validation-only or environment-dependent items

1. Execute PostgreSQL commit/rollback tests against a real target database.
2. Execute controlled Zabbix/Elasticsearch/Prometheus acceptance tests against target endpoints.
3. Execute a real Runbook tool + rollback + idempotency flow through the approved Tool Registry.
4. Connect and validate the organization's actual OIDC issuer/JWKS and identity-to-role propagation.
5. Validate pgvector extension and embedding dimension against the target offline PostgreSQL.
6. Promote a real immutable image through the internal registry with the organization's signing/verification implementation.
7. Execute Dashboard queries against populated production-like incident/audit/verification data.
8. Execute GitHub Actions on the current commit and resolve any runtime failures.
9. Remove all remaining historically tracked `__pycache__`/`.pyc` entries from every repository subtree; CI now prevents new additions.

## Measurement rule

Future Master alignment percentages must be based on direct repository inspection, this traceability file, tests and integration evidence. Placeholder files never count as full implementation.

## Definition of Done

A capability is fully aligned only when implementation, tests, error handling, security, audit, deployment and scenario acceptance are all present. Live infrastructure-dependent items remain `Implemented; validation required` until executed against the target environment.
