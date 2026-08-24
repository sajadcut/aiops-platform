# Implementation Status vs MASTER.md

Updated: 2026-08-25

This file is traceability evidence, not a replacement for `MASTER.md`. It distinguishes implemented code from capabilities that still require live environment validation.

## Latest gap-closure work completed

- Primary E2E workflow persists buffered audit events through `PostgreSQLAuditStore` before transaction completion.
- Approval create/get/approve/reject API now uses `PostgreSQLApprovalStore` rather than the process-local approval dictionary.
- Approval store contract tests added.
- Durable audit flush unit test added.
- CI now checks for tracked cache/bytecode/archive artifacts in addition to syntax and test suites.
- Existing durable workflow checkpoint, Incident/Finding/Evidence persistence, mandatory Evaluator, live Evidence collection, OIDC contract, pgvector validation, Dashboard API and offline deployment foundations remain in place.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/e2e_graph.py` + durable runtime | Integrated |
| Specialized agents | Triage/Application/Infrastructure/Kubernetes/Security/VM | Implemented |
| PostgreSQL persistence | SQLAlchemy + governance/workflow/incident migrations | Implemented; target runtime verification required |
| pgvector | model vectors + startup validation | Implemented; target extension/dimension validation required |
| Knowledge RAG | service + retrieval metadata + API | Integrated foundation |
| Operational Memory | service + namespace + E2E write-back | Integrated foundation |
| Context Builder | IncidentContext + normalization + EvidenceCollector | Integrated |
| Evidence | Zabbix + Elasticsearch + Prometheus aggregation | Integrated foundation; live target validation required |
| Hypothesis/RCA | evidence-linked contract + E2E RCA | Integrated foundation |
| Evaluator | mandatory `EvaluationGate` before Decision | Integrated |
| Decision Engine | policy/risk boundary | Implemented |
| Approval | PostgreSQL store + schema + durable lookup/resume + durable API | Integrated foundation; identity/audit verification pending |
| Execution | Tool Registry + policy + idempotency | Integrated foundation |
| Verification | VerificationEngine + VerificationGate | Integrated foundation |
| Audit | API + redaction + PostgreSQL store + primary-path durable flush | Integrated foundation; end-to-end transaction verification pending |
| Runbooks | governance + 3 MVP runbooks + registry + dry-run API | Integrated foundation; live tool/rollback execution still pending |
| Security/RBAC | deny-by-default + RBAC + API key + OIDC contract | Implemented foundation; enterprise issuer integration pending |
| Observability | connector/evidence layer | Integrated foundation; controlled environment validation pending |
| APIs | Master-aligned incident resources + execution/approval/runbook/audit + dashboard | Implemented foundation |
| Tests | unit + integration + scenario + failure-injection + durable approval/audit contracts | Improved; controlled environment acceptance pending |
| Offline deployment | Docker/Kubernetes/manifest contracts | Foundation; immutable signed image promotion pending |
| Dashboard | initial UI + summary API | Initial implementation; live KPI persistence queries pending |
| Workflow resume | PostgreSQL checkpoint store + durable runtime | Implemented foundation; LangGraph-native checkpoint plugin remains optional |
| Repository hygiene | `.gitignore` + cleanup script + CI enforcement | Controls implemented; pre-existing tracked cache/archive artifacts still require deletion |
| CI | syntax + unit/integration/scenario + hygiene gate | Workflow defined; current run result must be verified from GitHub Actions |

## Remaining high-impact gaps

1. Verify the primary E2E audit flush and Approval lifecycle against a real PostgreSQL database with commit/rollback assertions.
2. Persist all Incident/Finding/Evidence mutations in one lifecycle transaction where practical and add transaction rollback tests.
3. Execute controlled-environment Zabbix/Elasticsearch/Prometheus acceptance tests against real endpoints.
4. Complete Runbook tool execution, rollback and idempotency with approved Tool Registry mappings.
5. Complete enterprise OIDC/SSO issuer configuration and identity-to-role propagation.
6. Validate pgvector extension, embedding model and dimension against the offline target database.
7. Complete immutable image build, signing and promotion workflow for the internal registry.
8. Complete Dashboard live KPI queries from persistent incident/audit tables.
9. Delete all currently tracked `__pycache__`, `.pyc` and obsolete archive artifacts from the repository.
10. Run GitHub Actions on the current commit and resolve any real CI failures; repository inspection alone is not sufficient to claim a green build.

## Measurement rule

Future Master alignment percentages must be based on direct repository inspection, this traceability file, tests and integration evidence. Placeholder files never count as full implementation.

## Definition of Done

A capability is fully aligned only when implementation, tests, error handling, security, audit, deployment and scenario acceptance are all present. Live infrastructure-dependent items remain `Implemented; validation required` until executed against the target environment.
