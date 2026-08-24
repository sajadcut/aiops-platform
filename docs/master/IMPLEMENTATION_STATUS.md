# Implementation Status vs MASTER.md

Updated: 2026-08-25

This file records implementation evidence separately from the architecture contract in `MASTER.md`.
It must not be treated as a replacement for `MASTER.md`.

## Recent implementation batch

### Prior completed batch

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
15. Initial implementation-status baseline.

### Current 30-stage batch

1. Structured IncidentContext contract.
2. Evidence-linked Hypothesis contract.
3. Allowlisted operational EvidenceSourcePolicy.
4. Evidence normalization/filtering.
5. Prometheus evidence adapter.
6. Zabbix evidence normalization adapter.
7. Formal Evaluator thresholds.
8. Executable EvaluationGate.
9. Deterministic execution idempotency fingerprint.
10. Execution idempotency guard foundation.
11. Audit secret redaction utility.
12. Basic RBAC policy contract.
13. Runbook governance validator.
14. MVP application error rollback runbook.
15. MVP Kubernetes health inspection runbook.
16. MVP infrastructure observation runbook.
17. Explicit Verification gate contract.
18. Operational Memory namespace contract.
19. RAG retrieval metadata contract.
20. Incident lifecycle transition policy.
21. Context evidence policy tests.
22. Idempotency tests.
23. RBAC policy tests.
24. Runbook governance tests.
25. Verification gate tests.
26. Application error spike scenario fixture.
27. Kubernetes health scenario fixture.
28. Infrastructure pressure scenario fixture.
29. Offline artifact supply-chain manifest.
30. Updated implementation traceability record.

## Current implementation evidence

| MASTER capability | Current implementation | Status |
|---|---|---|
| Python + LangGraph core | `apps/orchestrator/graph.py`, `apps/orchestrator/e2e_graph.py` | Implemented foundation |
| Specialized agents | Triage/Application/Infrastructure/Kubernetes/Security/VM | Implemented |
| PostgreSQL persistence | SQLAlchemy async layer + domain models | Implemented; runtime verification required |
| pgvector model layer | KnowledgeDocument/MemoryEntry vector fields | Implemented; target extension/dimension verification required |
| Knowledge RAG | `KnowledgeRAGService` + retrieval contract | Implemented foundation |
| Operational Memory | `OperationalMemoryService` + namespace contract | Implemented foundation |
| Context Builder | `apps/context_service/builder.py` + IncidentContext + normalization | Implemented foundation |
| Evidence policy | Zabbix/Elasticsearch/Prometheus allowlist + normalization | Implemented foundation |
| Zabbix evidence | connector + evidence normalization | Implemented foundation; live verification required |
| Elasticsearch evidence | hardened client | Implemented foundation; live verification required |
| Prometheus evidence | connector + evidence adapter | Implemented foundation; live verification required |
| Evidence aggregation | `EvidenceCollector` + policy boundary | Implemented foundation |
| Hypothesis | evidence-linked domain contract | Implemented contract; RCA integration pending |
| RCA | E2E graph RCA node | Implemented foundation |
| Evaluator | `apps/evaluator`, thresholds, gate, guardrails, unit tests | Implemented foundation; mandatory graph wiring still pending |
| Decision Engine | `apps/decision_engine` | Implemented |
| Approval | In-memory service + PostgreSQL adapter | Transitional; durable workflow resume pending |
| Execution | `ExecutionService` + Tool Registry + policy/idempotency foundations | Implemented foundation |
| Verification | `VerificationEngine` + verification gate/tests | Implemented foundation |
| Audit | service/API + domain event + redaction | Implemented foundation; PostgreSQL persistence pending |
| Runbooks | governed contract + three MVP runbooks | Implemented foundation; runtime registry/dry-run/rollback execution pending |
| Security | deny-by-default policy + RBAC contract + tests | Foundation; API authentication/least privilege pending |
| Offline deployment | offline contract + artifact manifest | Foundation; actual immutable image pipeline/manifests pending |
| Scenario tests | three reference scenario fixtures + unit coverage | Improved; executable integration scenarios still pending |
| Dashboard | repository area exists | Incomplete |

## Remaining high-impact gaps

- Make Evaluator a mandatory node in `e2e_graph.py` before Decision.
- Persist Approval and Audit records in PostgreSQL and make workflow resume/idempotency durable.
- Connect the real `EvidenceCollector` output into ContextBuilder and Incident persistence.
- Register Runbooks in a runtime registry with owner/version/preconditions/timeout/rollback validation and dry-run tests.
- Add executable integration/scenario tests for Application Error Spike, Kubernetes Health/CrashLoop, and Infrastructure Pressure.
- Add API authentication, role enforcement and least-privilege checks at execution/approval boundaries.
- Add actual deployment manifests, health/readiness configuration and immutable internal image promotion flow.
- Validate pgvector availability and embedding dimensional compatibility in the target environment.
- Complete API coverage for context/evidence/knowledge/memory/plan/approval/verification endpoints.
- Complete dashboard support for Incident lifecycle and Automation status.

## Traceability rule

A capability is only considered fully aligned when implementation, tests, error handling, security, audit, deployment and scenario acceptance exist. A source file alone does not count as Done.
