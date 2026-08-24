# Implementation Status vs MASTER.md

Updated: 2026-08-25

This file records implementation evidence separately from the architecture contract in `MASTER.md`.
It must not be treated as a replacement for `MASTER.md`.

## Recent completed implementation stages

1. Evidence-aware Plan Evaluator contract.
2. Explicit ActionPlan domain contract.
3. PostgreSQL ApprovalStore adapter.
4. Structured AuditEvent domain contract.
5. Governed Runbook contract.
6. Deny-by-default execution policy boundary.
7. Normalized ContextBuilder.
8. Zabbix connector contract/offline mock.
9. Elasticsearch evidence retrieval hardening.
10. Live EvidenceCollector combining Zabbix, Elasticsearch and Prometheus.
11. Reusable OrchestrationGuardrails evaluator boundary.
12. Evaluator unit tests.
13. Execution policy security tests.
14. Offline production deployment contract.
15. This implementation-status baseline and traceability record.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/graph.py`, `apps/orchestrator/e2e_graph.py` | Implemented |
| Specialized agents | Triage/Application/Infrastructure/Kubernetes/Security/VM | Implemented |
| PostgreSQL persistence | SQLAlchemy async layer + domain models | Implemented |
| pgvector model layer | KnowledgeDocument/MemoryEntry vector fields | Implemented; environment verification required |
| Knowledge RAG | `KnowledgeRAGService` | Implemented |
| Operational Memory | `OperationalMemoryService` | Implemented |
| Context Builder | `apps/context_service/builder.py` | Implemented |
| Zabbix evidence boundary | `integrations/zabbix/client.py` | Implemented; live environment verification required |
| Elasticsearch evidence | `integrations/elasticsearch/client.py` | Implemented; live environment verification required |
| Prometheus evidence | `integrations/prometheus/client.py` | Implemented; live environment verification required |
| Evidence aggregation | `EvidenceCollector` | Implemented |
| RCA | E2E graph RCA node | Implemented |
| Evaluator | `apps/evaluator` + guardrails | Implemented foundation; E2E graph insertion still required |
| Decision Engine | `apps/decision_engine` | Implemented |
| Approval | In-memory service + PostgreSQL adapter | Transitional |
| Execution | `ExecutionService` + Tool Registry | Implemented foundation |
| Verification | `VerificationEngine` | Implemented foundation |
| Audit | Audit service + API + structured event contract | Implemented foundation; persistent store pending |
| Runbooks | Contract exists | Foundation; runtime registry/CRUD pending |
| Security policy | ToolPolicy + tests | Foundation |
| Offline deployment | deployment contract | Foundation; actual manifests/image pipeline pending |
| Scenario/integration tests | unit tests started | Incomplete |
| Dashboard | repository area exists | Incomplete |

## Important production gaps that remain

- Persist Approval and Audit records in PostgreSQL and make workflow resume/idempotency durable.
- Insert Evaluator as a mandatory E2E graph gate before Decision.
- Connect `EvidenceCollector` to the real Context Builder and incident lifecycle.
- Define and register up to three low-risk MVP Runbooks with rollback and dry-run support.
- Add failure-injection and scenario tests for the three MASTER reference incidents.
- Add security/RBAC authentication and least-privilege enforcement at API/tool boundaries.
- Add production deployment manifests and immutable internal-image promotion workflow.
- Validate pgvector extension and embedding dimension/model compatibility in the target environment.
- Complete dashboard/API coverage for incident context, evidence, knowledge, memory, plan, approval and verification.

## Traceability rule

A capability is only considered fully aligned when implementation, tests, error handling, security, audit, deployment and scenario acceptance exist. A source file alone does not count as Done.
