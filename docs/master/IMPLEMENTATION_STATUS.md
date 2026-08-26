# Implementation Status vs MASTER.md

Updated: 2026-08-26

This file is traceability evidence, not a replacement for `MASTER.md`. It distinguishes implemented repository capabilities from runtime acceptance that still needs evidence.

## Final production-readiness work implemented in repository

- Reproducible `requirements.txt` added so CI/build environments install the declared dependencies.
- Production liveness/readiness probes added: `/api/v1/health/live` and `/api/v1/health/ready`.
- OIDC signed JWT validation added with issuer, audience and JWKS verification; authenticated identity roles flow into RBAC permission checks.
- Controlled Observability connector acceptance harness added for Zabbix/Elasticsearch/Prometheus success/failure behavior.
- Health probe contract tests added.
- OIDC identity contract tests added.
- CI strengthened for reproducible dependency installation, syntax, unit/integration/scenario tests and repository hygiene.
- Automated repository-hygiene workflow added to remove tracked generated artifacts.
- Centralized runtime configuration contract is defined by the canonical root `/.env`; `domain/contracts/config.py` is schema/validation only and contains no runtime defaults.
- `.env.example` has been removed. CI consumes the tracked canonical `.env` directly and only mutates test values inside the ephemeral runner workspace.
- The committed `.env` contains non-secret defaults and empty secret placeholders only; CI rejects non-empty known secret fields in the tracked file.
- Zabbix, Elastic Agent Builder MCP and Prometheus adapters consume URL/credential/timeout settings only from centralized `settings` without independent hard-coded runtime fallbacks.
- Kubernetes Deployment consumes configuration through `aiops-platform-config` and `aiops-platform-secrets` via `envFrom`.
- Centralized configuration contract tests added.
- Governed Linux VM execution boundary added: read-only `vm_telemetry` plus high-risk `ssh_vm` with allow-listed actions and strict target/service validation.
- VM execution is MCP-backed; native SSH exists only behind the destination-side MCP/Edge trust boundary.
- Incident remediation API supports request → PostgreSQL approval → approved VM service restart → post-action verification.
- Remediation dry-run and action allow-listing are enforced at the API boundary.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/e2e_graph.py` + durable runtime | PASS (repository) |
| Specialized agents | Triage/Application/Infrastructure/Kubernetes/Security/VM plus additional specialists | PASS |
| PostgreSQL persistence | SQLAlchemy + governance/workflow/incident migrations | PASS (repository); target acceptance pending |
| pgvector | vector model + extension/type/dimension validation | PASS (repository); target DB validation pending |
| Knowledge RAG | service + retrieval metadata + API | PASS (repository) |
| Operational Memory | service + namespace + E2E write-back | PASS (repository) |
| Context Builder | IncidentContext + normalization + MCP-backed EvidenceCollector | PASS |
| Evidence | Zabbix + Elastic Agent Builder MCP + Prometheus + optional K8s/VM MCP aggregation | PASS (repository); target endpoint acceptance pending |
| Hypothesis/RCA | evidence-linked contract + E2E RCA | PASS |
| Evaluator | mandatory `EvaluationGate` before Decision | PASS |
| Decision Engine | policy/risk boundary | PASS |
| Approval | PostgreSQL store + durable lookup/resume + API | PASS (repository); target acceptance pending |
| Execution | Tool Registry + policy + idempotency + governed MCP-backed VM tool | PASS (repository); real target execution pending |
| Verification | VerificationEngine + fresh baseline + governed outcome | PASS (repository); live target validation pending |
| Audit | API + redaction + PostgreSQL store + primary-path flush | PASS (repository); live transaction acceptance pending |
| Runbooks | governance + MVP runbooks + strict registry + executor | PASS (repository); controlled real-tool/rollback acceptance pending |
| Security/RBAC | deny-by-default + API key + signed OIDC JWT + RBAC | PASS (repository); enterprise issuer acceptance pending |
| Observability | MCP external-tool boundary + Evidence layer | PASS (repository); target endpoint acceptance pending |
| APIs | Master-aligned incident resources + execution/approval/remediation/runbook/audit/dashboard | PASS (repository) |
| Health | `/health`, `/health/live`, `/health/ready` | PASS |
| Tests | unit + integration + scenario + failure-injection + security/config/MCP contracts | PASS (repository) |
| Centralized configuration | typed `Settings` schema + canonical tracked root `.env` + Kubernetes runtime projection + config tests | PASS (repository) |
| VM remediation | governed Tool → VM Edge MCP → destination-side action → verification | PASS (repository); live target acceptance pending |
| Offline deployment | Docker/Kubernetes + immutable digest attestation workflow | PASS (repository); internal registry signing/promotion pending |
| Dashboard | PostgreSQL-backed incident/approval/audit/verification KPIs + remediation action | PASS (repository); populated-data validation pending |
| Workflow resume | PostgreSQL checkpoint store + durable runtime | PASS application-level; restart test against real DB pending |
| Repository hygiene | `.gitignore` + cleanup workflow + tracked `.env` secret-placeholder guard | PASS (repository) |
| CI | reproducible dependency install + syntax/import/dependency + tests + database acceptance | PASS on verified heads; current head must remain green |

## Final acceptance items still requiring execution evidence

1. PostgreSQL HA/DR plus restart/resume against a target topology.
2. Controlled Zabbix/Elastic Agent Builder MCP/Prometheus contract tests against populated real endpoints.
3. Real VM Edge MCP execution with least-privilege destination credentials.
4. Real before/action/after recovery cycle against controlled targets.
5. Real Runbook tool execution, rollback and idempotency cycle through the Tool Registry.
6. Real OIDC issuer/JWKS integration and identity-to-role propagation.
7. pgvector extension/index/dimension validation against target PostgreSQL.
8. Immutable image signing/verification/promotion against the selected internal registry implementation.
9. Workload identity/mTLS lifecycle for MCP connections.
10. Load/soak/chaos and failure-isolation validation.

## Measurement rule

A capability is fully aligned only when implementation, tests, error handling, security, audit, deployment and acceptance evidence exist. Environment-dependent items are never marked fully verified without execution evidence.

## Definition of Done

No Placeholder or Foundation is considered Done. `FINAL_ACCEPTANCE_REPORT.md` is the authoritative checklist for the current acceptance batch; this file is the traceability summary.
