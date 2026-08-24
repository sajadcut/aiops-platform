# Implementation Status vs MASTER.md

Updated: 2026-08-25

This file is traceability evidence, not a replacement for `MASTER.md`. It distinguishes implemented repository capabilities from runtime acceptance that still needs evidence.

## Final production-readiness work implemented in repository

- Reproducible `requirements.txt` added so CI/build environments install the declared dependencies.
- Production liveness/readiness probes added: `/api/v1/health/live` and `/api/v1/health/ready`.
- OIDC signed JWT validation added with issuer, audience and JWKS verification; authenticated identity roles flow into RBAC permission checks.
- Controlled Observability connector acceptance harness added for Zabbix/Elasticsearch/Prometheus success/failure behavior.
- Health probe contract tests added.
- OIDC identity contract tests added.
- CI strengthened for reproducible dependency installation, syntax, unit/integration/scenario tests and repository hygiene.
- Automated repository-hygiene workflow added to remove tracked `__pycache__`, `.pyc`, `.pyo` and `.zip` artifacts on `main`.
- Tracked deployment `.env` containing a database password was removed.
- `FINAL_ACCEPTANCE_REPORT.md` added with requirement-by-requirement PASS/PENDING matrix.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/e2e_graph.py` + durable runtime | PASS (repository) |
| Specialized agents | Triage/Application/Infrastructure/Kubernetes/Security/VM | PASS |
| PostgreSQL persistence | SQLAlchemy + governance/workflow/incident migrations | PASS (repository); live transaction verification pending |
| pgvector | vector model + extension/type/dimension validation | PASS (repository); target DB validation pending |
| Knowledge RAG | service + retrieval metadata + API | PASS (repository) |
| Operational Memory | service + namespace + E2E write-back | PASS (repository) |
| Context Builder | IncidentContext + normalization + EvidenceCollector | PASS |
| Evidence | Zabbix + Elasticsearch + Prometheus aggregation | PASS (controlled harness); target endpoint acceptance pending |
| Hypothesis/RCA | evidence-linked contract + E2E RCA | PASS |
| Evaluator | mandatory `EvaluationGate` before Decision | PASS |
| Decision Engine | policy/risk boundary | PASS |
| Approval | PostgreSQL store + durable lookup/resume + API | PASS (repository); live commit/resume test pending |
| Execution | Tool Registry + policy + idempotency | PASS (repository); real target execution pending |
| Verification | VerificationEngine + VerificationGate | PASS |
| Audit | API + redaction + PostgreSQL store + primary-path flush | PASS (repository); live transaction test pending |
| Runbooks | governance + 3 MVP runbooks + registry + dry-run + executor | PASS (repository); controlled real-tool/rollback acceptance pending |
| Security/RBAC | deny-by-default + API key + signed OIDC JWT + RBAC | PASS (repository); enterprise issuer acceptance pending |
| Observability | connector/evidence layer + controlled harness | PASS (repository); target endpoint acceptance pending |
| APIs | Master-aligned incident resources + execution/approval/runbook/audit/dashboard | PASS (repository) |
| Health | `/health`, `/health/live`, `/health/ready` | PASS |
| Tests | unit + integration + scenario + failure-injection + OIDC/health/connector contracts | PASS (repository) |
| Offline deployment | Docker/Kubernetes + immutable digest attestation workflow | PASS (repository); internal registry signing/promotion pending |
| Dashboard | PostgreSQL-backed incident/approval/audit/verification KPIs + remediation action | PASS (repository); populated-data validation pending |
| Workflow resume | PostgreSQL checkpoint store + durable runtime | PASS application-level; restart test against real DB pending |
| Repository hygiene | `.gitignore` + cleanup script + cleanup workflow | CLEANUP AUTOMATION PRESENT; final main tree verification pending |
| CI | reproducible dependency install + syntax + tests + hygiene | DEFINED; current commit run must be verified |

## Final acceptance items still requiring execution evidence

1. PostgreSQL commit/rollback and restart/resume against a real ephemeral/target PostgreSQL instance.
2. Controlled Zabbix/Elasticsearch/Prometheus API contract tests (repository harness is present) plus populated endpoint acceptance.
3. Real Runbook tool execution, rollback and idempotency cycle through the Tool Registry.
4. Real OIDC issuer/JWKS integration and identity-to-role propagation.
5. pgvector extension/index/dimension validation against target PostgreSQL.
6. Immutable image signing/verification/promotion against the selected internal registry implementation.
7. GitHub Actions green result for the current `main` after cleanup automation executes.
8. Final repository-tree verification that no tracked generated artifacts remain.

## Measurement rule

A capability is fully aligned only when implementation, tests, error handling, security, audit, deployment and acceptance evidence exist. Environment-dependent items are never marked fully verified without execution evidence.

## Definition of Done

No Placeholder or Foundation is considered Done. `FINAL_ACCEPTANCE_REPORT.md` is the authoritative checklist for the current acceptance batch; this file is the traceability summary.
