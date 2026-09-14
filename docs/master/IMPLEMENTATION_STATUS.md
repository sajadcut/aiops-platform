# Implementation Status vs MASTER.md

Updated: 2026-09-14

This file is traceability evidence, not a replacement for `MASTER.md`. It distinguishes implemented repository capabilities from runtime acceptance that still needs evidence.

## Final production-readiness work implemented in repository

- Reproducible `requirements.txt` and container acceptance gates are present; exact dependency locking remains a separate reproducibility improvement.
- Production liveness/readiness probes exist at `/api/v1/health/live` and `/api/v1/health/ready`.
- OIDC signed JWT validation exists with issuer, audience and JWKS verification; authenticated identity roles flow into RBAC permission checks.
- Controlled Observability acceptance harnesses exist for Zabbix/Elasticsearch/Prometheus and broader operational scenarios.
- CI covers dependency installation, syntax/imports, unit/integration/scenario/security tests, database/pgvector acceptance and container supply-chain acceptance.
- Runtime configuration is centralized: `/.env.example` is the tracked non-secret contract, optional local `/.env` is untracked, and `domain/contracts/config.py` is the typed schema/validation layer.
- Kubernetes Deployment consumes environment-specific `aiops-platform-config` and `aiops-platform-secrets` via `envFrom`.
- Governed Linux VM execution boundary exists: read-only VM telemetry plus high-risk governed VM actions through the MCP/Edge trust boundary.
- Incident remediation supports request → durable approval → governed execution → fresh post-action verification.
- Remediation dry-run and action allow-listing are enforced at the API/execution boundary.
- Cognia is the only Governed Knowledge RAG in development, test and production. There is no local PostgreSQL/pgvector Knowledge retriever or provider switch.
- Cognia integration implements Application Client machine authentication, separate numeric Client Application Scope identity, opaque access-token lifecycle, explicit KB IDs, registration/idempotency, candidate Revision concurrency, Search Chunk traceability, optional Context Generation, typed upstream failures and no alternate-RAG fallback.
- Operational Memory remains independent in PostgreSQL/pgvector and is not moved into Cognia.
- Historical pre-Cognia Knowledge content, where present after migration, is retained only as a non-RAG archive without an embedding/retrieval path.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/e2e_graph.py` + durable runtime | PASS (repository) |
| Specialized agents | Triage plus modular specialist agents | PASS |
| PostgreSQL persistence | SQLAlchemy + governance/workflow/incident migrations | PASS (repository); target HA/DR acceptance pending |
| pgvector | extension/type/dimension validation for `memory_entries` only | PASS (repository); target DB validation pending |
| Knowledge RAG boundary | `KnowledgeRAGService` is Cognia-only; no runtime provider selector or local Knowledge retrieval path | PASS (repository) |
| Cognia governed Knowledge | Sole RAG: Application Client auth + authoring/Revision + Search + optional Context + readiness + fail-closed/no-alternate-RAG behavior | PASS (repository contract); **REAL ENV REQUIRED** for target Cognia acceptance |
| Operational Memory | service + namespace + E2E write-back, PostgreSQL/pgvector, separate from Knowledge RAG | PASS (repository) |
| Context Builder | IncidentContext + normalization + MCP-backed EvidenceCollector | PASS |
| Evidence | Zabbix + Elastic Agent Builder MCP + Prometheus + optional K8s/VM MCP aggregation | PASS (repository); target endpoint acceptance pending |
| Hypothesis/RCA | evidence-linked contract + E2E RCA | PASS |
| Evaluator | mandatory `EvaluationGate` before Decision | PASS |
| Decision Engine | policy/risk boundary | PASS |
| Approval | PostgreSQL store + durable lookup/resume + API | PASS (repository); target acceptance pending |
| Execution | Tool Registry + policy + idempotency + governed MCP-backed execution tools | PASS (repository); real target execution pending |
| Verification | VerificationEngine + fresh baseline + governed outcome | PASS (repository); live target validation pending |
| Audit | API + redaction + PostgreSQL store + primary-path flush | PASS (repository); live transaction acceptance pending |
| Runbooks | governance + MVP runbooks + strict registry + executor | PASS (repository); controlled real-tool/rollback acceptance pending |
| Security/RBAC | deny-by-default + API key + signed OIDC JWT + RBAC | PASS (repository); enterprise issuer acceptance pending |
| Observability | MCP external-tool boundary + Evidence layer | PASS (repository); target endpoint acceptance pending |
| APIs | Master-aligned incident resources + execution/approval/remediation/runbook/audit/dashboard | PASS (repository) |
| Health | `/health`, `/health/live`, `/health/ready`; Cognia is a required Production dependency because it is the sole Knowledge RAG | PASS (repository) |
| Tests | unit + integration + scenario + failure-injection + security/config/MCP/Cognia contracts | PASS only when current HEAD CI is green |
| Centralized configuration | typed `Settings` + tracked `.env.example` + untracked `.env` override + Kubernetes projection; no RAG provider selector | PASS (repository) |
| VM remediation | governed Tool → VM Edge MCP → destination-side action → verification | PASS (repository); live target acceptance pending |
| Offline deployment | hardened Docker/Kubernetes + immutable digest/container supply-chain gates | PASS (repository); internal registry promotion pending |
| Dashboard | PostgreSQL-backed incident/approval/audit/verification KPIs + remediation action | PASS (repository); populated-data validation pending |
| Workflow resume | PostgreSQL checkpoint store + durable runtime | PASS application-level; restart test against real DB pending |
| Repository hygiene | `.gitignore` + cleanup workflow + secret-placeholder/config guards | PASS (repository) |
| CI | syntax/import/dependency + tests + database acceptance + container acceptance | PASS on verified heads; current head must remain green |

## Final acceptance items still requiring execution evidence

1. Real Cognia HTTPS endpoint + Application Client authentication, assigned KB grants and Search against the exact configured KB IDs.
2. Cognia authorization negative tests plus General/ClientApplication/ExternalSubject Scope behavior where used by AIOps.
3. Cognia registration → Approval where required → Processing → Activated → Search lifecycle acceptance.
4. Cognia Search dependency/index outage behavior and proof that AIOps reports explicit degradation; no second RAG exists to substitute.
5. Cognia Context Generation sufficiency/traceability acceptance if an AIOps Context Profile is provisioned.
6. PostgreSQL HA/DR plus restart/resume against a target topology.
7. Controlled Zabbix/Elastic Agent Builder MCP/Prometheus contract tests against populated real endpoints.
8. Real VM/Kubernetes MCP execution with least-privilege destination credentials.
9. Real before/action/after recovery cycle against controlled targets.
10. Real Runbook tool execution, rollback and idempotency cycle through the Tool Registry.
11. Real OIDC issuer/JWKS integration and identity-to-role propagation.
12. pgvector extension/index/dimension validation against target PostgreSQL for Operational Memory.
13. Immutable image signing/verification/promotion against the selected internal registry implementation.
14. Workload identity/mTLS lifecycle for MCP connections.
15. Load/soak/chaos and failure-isolation validation.

## Measurement rule

A capability is fully aligned only when implementation, tests, error handling, security, audit, deployment and acceptance evidence exist. Environment-dependent items are never marked fully verified without execution evidence.

## Definition of Done

No Placeholder or Foundation is considered Done. `FINAL_ACCEPTANCE_REPORT.md` is the authoritative checklist for the current acceptance batch; this file is the traceability summary.
