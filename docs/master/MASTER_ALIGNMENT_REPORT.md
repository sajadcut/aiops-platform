# MASTER.md Alignment Report

## A) Gap Analysis

`MASTER.md` is treated as the Single Source of Truth.

| Area | Status | Notes |
|---|---|---|
| Repository architecture | 🟡 Existing and substantially aligned | Core Python/LangGraph/PostgreSQL structure exists; some legacy/extended modules remain. |
| Incident create/get/analyze contract | 🟢 Aligned | Canonical Incident lifecycle endpoints added. |
| Incident context/evidence/knowledge/memory/plan/verification | 🟢 Aligned | Existing resources retained and canonical lifecycle connected. |
| Approval | 🟢 Aligned | Incident approval API added; workflow approval is persisted to PostgreSQL. |
| Execution boundary | 🟢 Aligned | Execution service is the operational write boundary; caller/approval checks added. |
| Verification | 🟡 Aligned with persistence | Verification engine exists and results are now durably persisted. Its metric heuristic still needs scenario-specific hardening. |
| Audit | 🟡 Aligned | Durable PostgreSQL audit store is used on the primary lifecycle; direct standalone callers still buffer until flushed. |
| Knowledge RAG | 🟢 Aligned | PostgreSQL + pgvector; management/retrieval API added. |
| Operational Memory | 🟢 Aligned | PostgreSQL + pgvector; namespace/source metadata separation added. |
| Decision / Policy | 🟡 Aligned | Decision engine exists and policy decisions are now persisted; policy logic remains heuristic and should gain explicit policy records/allowlists. |
| Runbooks | 🟢 Aligned for MVP | List/create/get/dry-run/execute flows exist with validation and approval gate. Artifact storage remains file-based. |
| Tool Registry / Allowlist | 🟡 Aligned | Central execution boundary is enforced; registry still exposes all registered tools and should gain explicit per-agent allowlists. |
| Idempotency | 🟡 Partial | Runbook fingerprint replay exists; general execution idempotency remains process-local. |
| RBAC / OIDC / API key | 🟢 Existing and strengthened | Permissions expanded for Knowledge/Runbook management. |
| Zabbix/ELK/Prometheus evidence | 🟢 Existing | Connectors and EvidenceCollector already exist and are used by E2E orchestration. |
| LangGraph lifecycle | 🟢 Existing and aligned | Context → Triage → Parallel Agents → RCA → Evaluator → Decision → Approval/Execution → Verification → Memory. |
| PostgreSQL persistence | 🟢 Aligned | Canonical schema migration added and legacy incident evidence/findings copied. |
| Dashboard | 🟢 Existing | Existing summary/incidents APIs use canonical incidents/audit/verification tables. |
| MVP scenarios | 🟡 Framework exists | Application Error Spike / Kubernetes CrashLoop / Infrastructure Pressure paths exist, but full live scenario execution remains environment-dependent. |
| Offline deployment | 🟡 Existing infrastructure direction | Repository supports Docker/CI and LLM adapter abstraction; production offline acceptance is not executable from this audit environment. |

### Main legacy/out-of-contract areas retained

- `/api/v1/workflow/*`, `/api/v1/a2a/*`, `/api/v1/remediation/*`, `/api/v1/execute`, and direct approval APIs remain as extended/internal compatibility surfaces.
- The older `apps/orchestrator/graph.py` remains as a simpler workflow path; the canonical lifecycle is `apps/orchestrator/e2e_graph.py` plus `DurableWorkflowRuntime`.

## B) Files changed

- `apps/api/incidents.py`
- `apps/api/knowledge.py`
- `apps/api/main.py`
- `apps/api/runbook_execution.py`
- `apps/api/runbooks.py`
- `apps/execution_service/__init__.py`
- `apps/incident_service/repository.py`
- `apps/memory_service/__init__.py`
- `apps/orchestrator/runtime.py`
- `apps/runbook_service/executor.py`
- `apps/runbook_service/registry.py`
- `apps/security/rbac.py`
- `database/migrations/versions/g7h8i9j0k1l2_master_schema_alignment.py`
- `domain/models.py`
- `domain/runbook_validation.py`
- `tests/integration/test_master_api_surface.py`

## C) Files added

- `apps/api/knowledge.py`
- `database/migrations/versions/g7h8i9j0k1l2_master_schema_alignment.py`
- `docs/master/MASTER_ALIGNMENT_REPORT.md`

## D) Major implementation changes

The branch implements the canonical Incident API lifecycle, Knowledge API, canonical PostgreSQL incident/evidence/finding tables, durable workflow approval, policy/action-plan/verification persistence, governed execution, runbook approval enforcement, stronger runbook validation, and Operational Memory namespace separation.

## E) Canonical API contract

### Master public contract

- `POST /api/v1/incidents`
- `GET /api/v1/incidents/{id}`
- `POST /api/v1/incidents/{id}/analyze`
- `GET /api/v1/incidents/{id}/context`
- `GET /api/v1/incidents/{id}/evidence`
- `GET /api/v1/incidents/{id}/knowledge`
- `GET /api/v1/incidents/{id}/memory`
- `GET /api/v1/incidents/{id}/plan`
- `POST /api/v1/incidents/{id}/approve`
- `POST /api/v1/incidents/{id}/execute`
- `GET /api/v1/incidents/{id}/verification`
- `GET/POST /api/v1/runbooks`
- `GET/POST /api/v1/knowledge`
- `GET /api/v1/health`

### Extended compatibility APIs retained

- `/api/v1/incidents/analyze`
- `/api/v1/incidents/{id}/remediate`
- `/api/v1/approvals/*`
- `/api/v1/execute`
- `/api/v1/runbooks/{id}/execute`
- `/api/v1/runbooks/{id}/dry-run`
- `/api/v1/workflow/*`
- `/api/v1/e2e/*`
- `/api/v1/a2a/*`
- `/api/v1/audit/*`
- `/api/v1/dashboard/*`

## F) DB / Migration changes

Migration `g7h8i9j0k1l2_master_schema_alignment` aligns the legacy governance schema with the canonical ORM contract, creates `evidences` and `findings`, preserves/copies legacy operational records, and adds durable `action_plans`, `policy_decisions`, `execution_results`, and `verification_results` persistence.

Knowledge and Memory remain in PostgreSQL + pgvector with vector dimension 1536.

## G) Test plan

1. Import/startup and route-surface tests.
2. `compileall` syntax validation.
3. Unit tests for policy/state/tool contracts.
4. Integration tests for PostgreSQL + pgvector + migrations.
5. Scenario tests for Application Error Spike, Kubernetes CrashLoop, Infrastructure Pressure.
6. Approval/Execution/Verification safety tests.
7. RBAC/OIDC and runbook validation tests.
8. Failure injection for missing evidence, execution failure, verification failure and connector timeouts.

## H) Commands

```powershell
python -m pip install -r requirements.txt
python -m alembic -c database/migrations/alembic.ini upgrade head
python -m compileall agents apps domain integrations knowledge memory tests
python -m pytest -q tests/unit tests/integration tests/scenarios
```

For a local PostgreSQL acceptance run, set `DATABASE_URL`/`ALEMBIC_DATABASE_URL` to the local PostgreSQL instance with pgvector installed, then run the migration and tests above.

## I) Alignment estimate

Current code-level alignment is estimated at **~82%** against the full `MASTER.md` scope.

The percentage is deliberately not presented as a test-passed score: full acceptance depends on executing the repository's CI, PostgreSQL migration acceptance, and live observability/VM integration scenarios.

## J) Open issues

1. General execution idempotency is still process-local; a durable idempotency key/unique constraint should be added for cross-process guarantees.
2. Tool Registry needs explicit per-agent allowlists instead of returning every registered tool from `get_allowed_tools`.
3. Decision/Policy logic is still heuristic; policy records exist but a formal persisted policy model and policy-version evaluation should be added before production auto-execution.
4. Runbook management writes repository YAML artifacts; for a stronger production architecture, runbook definitions should be persisted/governed in PostgreSQL or a controlled artifact store.
5. Verification heuristics should become scenario-aware (HTTP error rate, K8s readiness, VM CPU/disk etc.) rather than relying on generic numeric improvement rules.
6. Full CI results were not available during this pass; the PR is intentionally left as a draft so repository Quality and Database Acceptance workflows can validate the changes.
