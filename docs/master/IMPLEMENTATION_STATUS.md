# Implementation Status vs MASTER.md

Updated: 2026-08-25

This file records implementation evidence separately from the architecture contract in `MASTER.md`.
It is not a replacement for `MASTER.md`.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/graph.py`, `apps/orchestrator/e2e_graph.py` | Integrated MVP foundation |
| Specialized agents | Triage/Application/Infrastructure/Kubernetes/Security/VM | Implemented |
| PostgreSQL persistence | SQLAlchemy + domain models + governance migration | Implemented; target runtime verification required |
| pgvector | KnowledgeDocument/MemoryEntry vectors | Implemented; extension/dimension verification required |
| Knowledge RAG | `KnowledgeRAGService` + retrieval metadata contract + API | Integrated foundation |
| Operational Memory | `OperationalMemoryService` + namespace + E2E write-back + API | Integrated foundation |
| Context Builder | IncidentContext + normalization + EvidenceCollector path | Integrated foundation |
| Zabbix evidence | connector + normalized evidence | Integrated foundation; live verification required |
| Elasticsearch evidence | hardened connector | Integrated foundation; live verification required |
| Prometheus evidence | connector + evidence adapter | Integrated foundation; live verification required |
| Evidence aggregation | `EvidenceCollector` | Connected to primary E2E context node |
| Hypothesis | evidence-linked domain contract | Contract implemented; richer RCA ranking pending |
| RCA | E2E graph RCA node | Integrated foundation |
| Evaluator | `EvaluationGate` is a mandatory E2E node before Decision | Integrated MVP gate |
| Decision Engine | policy-based decision boundary | Implemented |
| Approval | In-memory service + PostgreSQL store + schema migration | Transitional; durable cross-process resume pending |
| Execution | ExecutionService + Tool Registry + policy + idempotency | Integrated foundation |
| Verification | VerificationEngine + VerificationGate | Integrated foundation |
| Audit | service/API + redaction + PostgreSQL store + schema migration | Integrated foundation; graph-to-DB flush pending |
| Runbooks | governance validator + 3 MVP runbooks + runtime registry + dry-run API | Integrated foundation; real tool/rollback execution pending |
| Security/RBAC | deny-by-default policy + RBAC + API key/role dependency + protected execution API | Implemented foundation; enterprise SSO pending |
| Offline deployment | artifact manifest + offline Docker contract + Kubernetes deployment/probes | Foundation implemented; immutable promotion/signing pipeline pending |
| Scenario/failure tests | unit + E2E safety + failure-injection + reference fixtures | Improved; full controlled-environment connector scenarios pending |
| Dashboard | initial incident operations dashboard | Initial implementation |
| Master-aligned APIs | context/evidence/knowledge/memory/plan/verification/audit/runbook endpoints | Implemented foundation |
| Repository hygiene | `.gitignore` + cleanup script | Added; existing tracked cache artifacts still require deletion commit |
| CI | syntax + unit/integration/scenario GitHub Actions workflow | Added; runtime CI result not yet verified in this environment |

## Remaining high-impact gaps

1. Durable LangGraph checkpoint/workflow resume with PostgreSQL.
2. Persist graph Audit events directly to PostgreSQL in the primary E2E path.
3. Replace the in-memory approval lookup in the E2E resume path with the PostgreSQL approval store.
4. Persist Incident/Finding/Evidence records as first-class lifecycle objects during E2E processing.
5. Real production configuration and controlled-environment validation for Zabbix/Elasticsearch/Prometheus.
6. Runbook tool execution, dry-run enforcement and rollback execution with runbook-level idempotency.
7. Enterprise authentication/SSO and identity propagation beyond the basic internal API key/RBAC contract.
8. Complete scenario acceptance tests against controlled observability and execution environments.
9. pgvector extension/model-dimension validation in the offline target environment.
10. Immutable internal image build, signing and promotion workflow.
11. Dashboard live KPI sources and incident lifecycle UX.
12. Remove tracked `__pycache__`, `.pyc` and obsolete archive artifacts from Git history/working tree.

## Definition-of-Done rule

A capability is only fully aligned when implementation, tests, error handling, security, audit, deployment and scenario acceptance exist. A source file or placeholder contract alone does not count as Done.

## Measurement rule

Future Master alignment percentages must be based on direct repository inspection plus this status file, with separate scoring for architecture, integrated behavior, persistence, tests, security and production readiness. Placeholder files must not be treated as full implementation.
