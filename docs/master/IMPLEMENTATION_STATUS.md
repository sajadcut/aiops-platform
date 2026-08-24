# Implementation Status vs MASTER.md

Updated: 2026-08-25

This file is traceability evidence, not a replacement for `MASTER.md`. It distinguishes implemented code from capabilities that still require live environment validation.

## Gap-closure batch completed

- Durable PostgreSQL workflow checkpoint store and resumable runtime.
- First-class PostgreSQL persistence for Incident, Finding and Evidence.
- Durable PostgreSQL ApprovalStore lookup for cross-process approval resume.
- Mandatory Evaluator gate in primary E2E graph.
- Live EvidenceCollector connected to primary E2E Context node.
- Primary Incident analyze API routed through `DurableWorkflowRuntime`.
- PostgreSQL governance migration extended for workflow and incident lifecycle data.
- Provider-neutral OIDC identity contract plus internal API-key/RBAC fallback.
- pgvector startup validation contract.
- Operational dashboard summary API.
- CI quality workflow already present for syntax/unit/integration/scenario tests.
- Repository cache hygiene controls already present; historical tracked artifacts still require cleanup execution.

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
| Approval | PostgreSQL store + schema + durable lookup/resume runtime | Implemented foundation; approval API still needs full identity/audit integration |
| Execution | Tool Registry + policy + idempotency | Integrated foundation |
| Verification | VerificationEngine + VerificationGate | Integrated foundation |
| Audit | API + redaction + PostgreSQL store | Integrated foundation; primary-path DB flush still requires completion |
| Runbooks | governance + 3 MVP runbooks + registry + dry-run API | Integrated foundation; live tool/rollback execution still pending |
| Security/RBAC | deny-by-default + RBAC + API key + OIDC contract | Implemented foundation; enterprise issuer integration pending |
| Observability | connector/evidence layer | Integrated foundation; controlled environment validation pending |
| APIs | Master-aligned incident resources + execution/approval/runbook/audit + dashboard | Implemented foundation |
| Tests | unit + integration + scenario + failure-injection | Improved; controlled environment acceptance pending |
| Offline deployment | Docker/Kubernetes/manifest contracts | Foundation; immutable signed image promotion pending |
| Dashboard | initial UI + summary API | Initial implementation |
| Workflow resume | PostgreSQL checkpoint store + durable runtime | Implemented foundation; LangGraph-native checkpoint plugin can be added when target dependency baseline is fixed |
| Repository hygiene | `.gitignore` + cleanup script | Controls present; tracked historical cache/archive cleanup still pending |

## Remaining high-impact gaps

1. Persist every E2E Audit event directly to PostgreSQL in the primary transaction boundary.
2. Complete durable Approval API flow so approve/reject writes PostgreSQL and resume uses it exclusively.
3. Persist all Incident/Finding/Evidence mutations in the same lifecycle transaction where practical.
4. Execute controlled-environment Zabbix/Elasticsearch/Prometheus acceptance tests against real endpoints.
5. Complete Runbook tool execution, rollback and idempotency with approved Tool Registry mappings.
6. Complete enterprise OIDC/SSO issuer configuration and identity-to-role propagation.
7. Validate pgvector extension, embedding model and dimension against the offline target database.
8. Complete immutable image build, signing and promotion pipeline for the internal registry.
9. Complete dashboard live KPI queries against persistent incident/audit tables.
10. Remove tracked `__pycache__`, `.pyc` and obsolete archive artifacts from the repository.
11. Run GitHub Actions on the current commit and resolve any real CI failures; this environment cannot assert a green run without a reported workflow result.

## Measurement rule

Future Master alignment percentages must be based on direct repository inspection, this traceability file, tests and integration evidence. Placeholder files never count as full implementation.

## Definition of Done

A capability is fully aligned only when implementation, tests, error handling, security, audit, deployment and scenario acceptance are all present. Live infrastructure-dependent items remain `Implemented; validation required` until executed against the target environment.
