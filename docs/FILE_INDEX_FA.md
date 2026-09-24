# FILE INDEX فارسی — aiops-platform

> این فایل فهرست فایل‌به‌فایل repository است. توضیح معماری و flow در `CODEBASE_GUIDE_FA.md` آمده است.
> این فایل با `scripts/generate_file_index_fa.py` ساخته و در CI کنترل می‌شود.

**تعداد فایل‌های track‌شده و پوشش‌داده‌شده: 486**

| Path | Type | Purpose | Called By | Calls/Depends On | Runtime/Test/Docs | Notes |
|---|---|---|---|---|---|---|
| `.dockerignore` | File | فایل پروژه | — | — | Other |  |
| `.env.example` | File | فایل پروژه | — | — | Other |  |
| `.github/workflows/chatbot-acceptance.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/container-acceptance.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/documentation-index.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/image-signing.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/quality.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/repository-hygiene.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.gitignore` | Git | قواعد عدم track فایل‌های generated/local | Git | repository hygiene | Tooling | رفتار runtime ندارد |
| `FINAL_ACCEPTANCE_REPORT.md` | Report | گزارش acceptance بر پایه evidence | تیم | MASTER و tests | Docs | جای MASTER را نمی‌گیرد |
| `INCIDENT_COVERAGE_MATRIX.md` | File | فایل پروژه | — | — | Other |  |
| `MASTER.md` | SSoT | قرارداد معماری، Requirementها و Acceptance اصلی پروژه | تیم و CI | کل معماری | Docs | Single Source of Truth |
| `OPERATIONAL_ACCEPTANCE.md` | File | فایل پروژه | — | — | Other |  |
| `PRODUCTION_ACCEPTANCE.md` | File | فایل پروژه | — | — | Other |  |
| `README.md` | File | فایل پروژه | — | — | Other |  |
| `agents/README.md` | Docs | راهنمای Agent layer و نقش Agentها | توسعه‌دهنده | agents/* | Docs | مرجع لایه Agent |
| `agents/__init__.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/application/__init__.py` | Python | Agent تخصصی application برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/application/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/application/investigation.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/change/__init__.py` | Python | Agent تخصصی change برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/change/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/database/__init__.py` | Python | Agent تخصصی database برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/database/adapters/__init__.py` | Python | Agent تخصصی database برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/database/adapters/postgresql.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/database/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/dependency/__init__.py` | Python | Agent تخصصی dependency برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/dependency/core.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/dependency/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/identity/__init__.py` | Python | Agent تخصصی identity برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/identity/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/identity/safety.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/infrastructure/__init__.py` | Python | Agent تخصصی infrastructure برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/infrastructure/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/kubernetes/__init__.py` | Python | Agent تخصصی kubernetes برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/kubernetes/diagnostics.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/kubernetes/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/kubernetes/pipeline.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/kubernetes/resource_analyzers.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/kubernetes/safety.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/messaging/__init__.py` | Python | Agent تخصصی messaging برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/messaging/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/network/__init__.py` | Python | Agent تخصصی network برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/network/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/recovery/__init__.py` | Python | Agent تخصصی recovery برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/recovery/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/security/__init__.py` | Python | Agent تخصصی security برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/security/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/security/enrichment.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/security/safety.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/shared/a2a_agent.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/base.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/coordinator.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/domain_agent.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/intelligence.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/registry.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/telemetry.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/storage/__init__.py` | Python | Agent تخصصی storage برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/storage/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/triage/__init__.py` | Python | Agent تخصصی triage برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/triage/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/vm/__init__.py` | Python | Agent تخصصی vm برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/vm/deterministic.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/vm/engine.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `apps/README.md` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/__init__.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/alert_gateway/__init__.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/api/__init__.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/a2a.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/agents.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/audit.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/chatbot.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/cognia_scope.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/dashboard.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/dashboard_incidents.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/database_guard.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/e2e_workflow.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/execution.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/health.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/http_logging.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/incident_resources.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/incidents.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/main.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/remediation.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/runbook_execution.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/runbooks.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/signals.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/workflow.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/approval_service/__init__.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/approval_service/binding.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/approval_service/execution_claim.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/approval_service/postgres.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/approval_service/store.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/audit_service/__init__.py` | Python | Audit: ثبت، redaction و persistence Audit | boundaryهای حساس | PostgreSQL | Runtime | برای traceability و forensic |
| `apps/audit_service/postgres.py` | Python | Audit: ثبت، redaction و persistence Audit | boundaryهای حساس | PostgreSQL | Runtime | برای traceability و forensic |
| `apps/audit_service/redaction.py` | Python | Audit: ثبت، redaction و persistence Audit | boundaryهای حساس | PostgreSQL | Runtime | برای traceability و forensic |
| `apps/chatbot/__init__.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/chatbot/errors.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/chatbot/models.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/chatbot/reliable_service.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/chatbot/service.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/chatbot/store.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/chatbot/streaming.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/chatbot/tools.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/context_service/__init__.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/asset_identity.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/builder.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/evidence_collector.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/knowledge_topology.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/normalizer.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/source_policy.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/database/pgvector_contract.py` | Python | DB: قرارداد/validation pgvector فقط برای Operational Memory | startup/CI | PostgreSQL | Runtime | memory schema/dimension guard |
| `apps/database/vector_validation.py` | Python | DB: قرارداد/validation pgvector فقط برای Operational Memory | startup/CI | PostgreSQL | Runtime | memory schema/dimension guard |
| `apps/decision_engine/__init__.py` | Python | Decision: تبدیل RCA/evaluation به تصمیم و risk | Orchestrator | evaluation/policy | Runtime | LLM authority نیست |
| `apps/evaluator/__init__.py` | Python | Evaluator: Critic/evaluator gate برای کیفیت RCA | Orchestrator | agent findings/thresholds | Runtime | قبل از decision |
| `apps/evaluator/gate.py` | Python | Evaluator: Critic/evaluator gate برای کیفیت RCA | Orchestrator | agent findings/thresholds | Runtime | قبل از decision |
| `apps/evaluator/thresholds.py` | Python | Evaluator: Critic/evaluator gate برای کیفیت RCA | Orchestrator | agent findings/thresholds | Runtime | قبل از decision |
| `apps/execution_service/__init__.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/idempotency.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/policy.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/base.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/kubernetes_mcp.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/mock_executor.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/registry.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/ssh_vm.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/vm_telemetry.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/incident_service/repository.py` | Python | Persistence: Repository durable Incident/Evidence/Finding | signal/workflow/dashboard | SQLAlchemy/PostgreSQL | Runtime | هسته persistence incident |
| `apps/mcp_server/__init__.py` | Python | MCP: MCP server داخلی برای expose ابزارهای کنترل‌شده | MCP clients | provider adapters/security | Runtime | capability boundary |
| `apps/mcp_server/main.py` | Python | MCP: MCP server داخلی برای expose ابزارهای کنترل‌شده | MCP clients | provider adapters/security | Runtime | capability boundary |
| `apps/memory_service/__init__.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/memory_service/builder.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/memory_service/consolidation.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/memory_service/contracts.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/memory_service/feedback.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/memory_service/quality.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/memory_service/retrieval.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/memory_service/telemetry.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/operator_summary.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/orchestrator/a2a_gateway.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/e2e_graph.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/graph.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/guardrails.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/learning_runtime.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/learning_signal_aware.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/runtime.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/signal_aware.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/workflow_store.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/rag_service/__init__.py` | Python | RAG: Knowledge RAG canonical با Cognia Search/Context/authoring contract | Workflow/agents/API | Cognia + provider contract | Runtime | دانش رسمی، جدا از memory و live Evidence |
| `apps/remediation_planner/__init__.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/runbook_service/executor.py` | Python | Runbook: Registry/Executor runbookهای allow-listed | API/execution workflow | domain/runbooks/execution | Runtime | اجرای کنترل‌شده |
| `apps/runbook_service/learning.py` | Python | Runbook: Registry/Executor runbookهای allow-listed | API/execution workflow | domain/runbooks/execution | Runtime | اجرای کنترل‌شده |
| `apps/runbook_service/registry.py` | Python | Runbook: Registry/Executor runbookهای allow-listed | API/execution workflow | domain/runbooks/execution | Runtime | اجرای کنترل‌شده |
| `apps/runbook_service/runtime_guard.py` | Python | Runbook: Registry/Executor runbookهای allow-listed | API/execution workflow | domain/runbooks/execution | Runtime | اجرای کنترل‌شده |
| `apps/security/auth.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/security/oidc.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/security/rbac.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/security/token_validator.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/signal_gateway/__init__.py` | Python | Signal: ورود، normalization، correlation و dedupe سیگنال | API/webhooks | incident repository/context | Runtime | ابتدای Incident flow |
| `apps/signal_gateway/correlation.py` | Python | Signal: ورود، normalization، correlation و dedupe سیگنال | API/webhooks | incident repository/context | Runtime | ابتدای Incident flow |
| `apps/signal_gateway/elastic_anomaly.py` | Python | Signal: ورود، normalization، correlation و dedupe سیگنال | API/webhooks | incident repository/context | Runtime | ابتدای Incident flow |
| `apps/signal_gateway/prometheus_alertmanager.py` | Python | Signal: ورود، normalization، correlation و dedupe سیگنال | API/webhooks | incident repository/context | Runtime | ابتدای Incident flow |
| `apps/signal_gateway/zabbix_lifecycle.py` | Python | Signal: ورود، normalization، correlation و dedupe سیگنال | API/webhooks | incident repository/context | Runtime | ابتدای Incident flow |
| `apps/verification_service/__init__.py` | Python | Verify: Verification مستقل پس از remediation | Workflow/execution | live evidence/audit | Runtime | tool success برابر recovery نیست |
| `dashboards/__init__.py` | Python | package marker dashboard | Python | — | Tooling | رفتار مستقل ندارد |
| `dashboards/agents.html` | HTML | پوسته و layout داشبورد | FastAPI static route | CSS/JS/API | Runtime UI | صفحه اپراتوری |
| `dashboards/approval-actions.css` | CSS | استایل Control Center و کنترل‌های عملیاتی | Browser | HTML classes | Runtime UI | بدون داده fake |
| `dashboards/approval-actions.js` | JS | state، API binding و interaction داشبورد | Browser | /api/v1 endpoints | Runtime UI | action حساس backend-governed است |
| `dashboards/chatbot-transport.js` | JS | state، API binding و interaction داشبورد | Browser | /api/v1 endpoints | Runtime UI | action حساس backend-governed است |
| `dashboards/chatbot-ui.js` | JS | state، API binding و interaction داشبورد | Browser | /api/v1 endpoints | Runtime UI | action حساس backend-governed است |
| `dashboards/chatbot.css` | CSS | استایل Control Center و کنترل‌های عملیاتی | Browser | HTML classes | Runtime UI | بدون داده fake |
| `dashboards/chatbot.html` | HTML | پوسته و layout داشبورد | FastAPI static route | CSS/JS/API | Runtime UI | صفحه اپراتوری |
| `dashboards/chatbot.js` | JS | state، API binding و interaction داشبورد | Browser | /api/v1 endpoints | Runtime UI | action حساس backend-governed است |
| `dashboards/control-center.css` | CSS | استایل Control Center و کنترل‌های عملیاتی | Browser | HTML classes | Runtime UI | بدون داده fake |
| `dashboards/control-center.js` | JS | state، API binding و interaction داشبورد | Browser | /api/v1 endpoints | Runtime UI | action حساس backend-governed است |
| `dashboards/index.html` | HTML | پوسته و layout داشبورد | FastAPI static route | CSS/JS/API | Runtime UI | صفحه اپراتوری |
| `database/__init__.py` | Python | Engine/session factory پایگاه‌داده | repository/storeها | SQLAlchemy/.env | Runtime | اتصال مرکزی PostgreSQL |
| `database/migration_validation.py` | File | فایل پروژه | — | — | Other |  |
| `database/migrations/README` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/alembic.ini` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/env.py` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/script.py.mako` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/versions/0ee48995b0c1_add_rag_and_memory_tables.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/34ec6bd70cb3_initial_migration_incident_evidence_.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/bce19e0dbd2d_fix_embedding_column_type.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/c3d4e5f6a7b8_retire_local_knowledge_rag.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/f1a2b3c4d5e6_add_operational_persistence.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/f2b3c4d5e6f7_approval_consumed_state.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/f3c4d5e6f7a8_add_chatbot_persistence.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/g4d5e6f7a8b9_chatbot_operations_copilot_v2.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/h5e6f7a8b9c0_operational_memory_v2.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/i6f7a8b9c0d1_memory_episode_idempotency.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/j7g8h9i0j1k2_distributed_rate_limits.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `deployment/__init__.py` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/docker/offline/ARTIFACT_MANIFEST.md` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/docker/offline/Dockerfile` | Docker | ساخت image آفلاین پلتفرم | Docker/CI | requirements/repo | Deploy | برای شبکه محدود |
| `deployment/docker/offline/README.md` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/kubernetes/aiops-platform.yaml` | K8s | Manifest/نمونه config استقرار | Kubernetes/OpenShift | image/.env/secrets | Deploy | runtime deployment |
| `deployment/kubernetes/configuration.example.yaml` | K8s | Manifest/نمونه config استقرار | Kubernetes/OpenShift | image/.env/secrets | Deploy | runtime deployment |
| `deployment/kubernetes/memory-embedding-backfill-cronjob.yaml` | K8s | Manifest/نمونه config استقرار | Kubernetes/OpenShift | image/.env/secrets | Deploy | runtime deployment |
| `deployment/kubernetes/memory-stale-cronjob.yaml` | K8s | Manifest/نمونه config استقرار | Kubernetes/OpenShift | image/.env/secrets | Deploy | runtime deployment |
| `deployment/kubernetes/migrate-job.yaml` | K8s | Manifest/نمونه config استقرار | Kubernetes/OpenShift | image/.env/secrets | Deploy | runtime deployment |
| `deployment/logrotate/aiops-platform` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/systemd/aiops-logrotate.service` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/systemd/aiops-logrotate.timer` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `docs/BENCHMARK_2026.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CHATBOT.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CHATBOT_UI_V3.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CHATBOT_UI_V3_ACCEPTANCE.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CODEBASE_GUIDE_FA.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CODE_SYMBOLS_FA.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/COGNIA_INTEGRATION.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CONFIGURATION.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/DEPLOYMENT.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/DOTIN_GENERAL_CHATBOT.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/ELASTIC_ANOMALY_INGESTION.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/FILE_INDEX_FA.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/INCIDENT_TIMELINE_LOGGING.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/LOGGING.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/MULTI_SOURCE_REASONING.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/NEXT_TASK.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/OPERATIONAL_MEMORY_V2.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/OPERATIONS_COPILOT_V2.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/PRODUCTION_ACCEPTANCE_MATRIX.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/PRODUCTION_HARDENING_WIP.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/PROJECT_STATE.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/PROMETHEUS_ALERTMANAGER_INGESTION.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/SERVICE_TOPOLOGY_KNOWLEDGE.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/UPSTREAM_MCP_PROVIDERS.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/VM_REMEDIATION.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/ZABBIX_SIGNAL_LIFECYCLE.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/__init__.py` | Python | package marker docs | Python | — | Docs | رفتار runtime ندارد |
| `docs/adr/ADR-017-UPSTREAM-MCP-PROVIDERS.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/adr/DECISIONS.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/master/IMPLEMENTATION_STATUS.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/master/MASTER.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `domain/__init__.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/action_plan.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/audit_event.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/contracts/config.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/contracts/context.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/contracts/exceptions.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/contracts/logging.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/contracts/rate_limit.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/contracts/redaction.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/contracts/retry.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/hypothesis.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/idempotency.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/incident_context.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/incident_transition.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/models.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/observability.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/runbook.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/runbook_validation.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/schemas.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/verification_gate.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `integrations/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/base.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/cognia/__init__.py` | Python | Cognia canonical Governed Knowledge client: machine auth/Search/Context/authoring | RAG service/readiness | Cognia HTTP/.env | Runtime | opaque token، explicit KB/Scope، no hidden fallback |
| `integrations/cognia/client.py` | Python | Cognia canonical Governed Knowledge client: machine auth/Search/Context/authoring | RAG service/readiness | Cognia HTTP/.env | Runtime | opaque token، explicit KB/Scope، no hidden fallback |
| `integrations/elasticsearch/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/elasticsearch/client.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/elasticsearch/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `integrations/http_transport.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/jenkins/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/jenkins/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `integrations/kubernetes/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/kubernetes/client.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/kubernetes/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `integrations/llm/base.py` | Python | Adapter provider LLM | Agents/evaluator | HTTP/provider config | Runtime | LLM فقط reasoning |
| `integrations/llm/mock_provider.py` | Python | Adapter provider LLM | Agents/evaluator | HTTP/provider config | Runtime | LLM فقط reasoning |
| `integrations/llm/openai_compatible.py` | Python | Adapter provider LLM | Agents/evaluator | HTTP/provider config | Runtime | LLM فقط reasoning |
| `integrations/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `integrations/prometheus/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/prometheus/client.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/prometheus/evidence.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/prometheus/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `integrations/vm/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/vm/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `integrations/vm/service_adapters.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/vm/ssh_connector.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/vm/target_context.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/client.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/evidence.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `knowledge/__init__.py` | Python | Contract/helper لایه Cognia-only Knowledge RAG | RAG service | Cognia retrieval contract | Runtime | دانش رسمی governed فقط از Cognia |
| `knowledge/retrieval_contract.py` | Python | Contract/helper لایه Cognia-only Knowledge RAG | RAG service | Cognia retrieval contract | Runtime | دانش رسمی governed فقط از Cognia |
| `memory/__init__.py` | Python | Namespace/contract Operational Memory | Memory service | pgvector | Runtime | تجربه incidentهای قبلی |
| `memory/namespace.py` | Python | Namespace/contract Operational Memory | Memory service | pgvector | Runtime | تجربه incidentهای قبلی |
| `operational.env.example` | File | فایل پروژه | — | — | Other |  |
| `requirements-dev.txt` | File | فایل پروژه | — | — | Other |  |
| `requirements.txt` | Deps | فهرست dependencyهای Python | pip/CI/Docker | runtime packages | Build | ورودی نصب dependency |
| `runbooks/README.md` | Docs | راهنما/package runbooks | توسعه‌دهنده | runbooks/* | Docs | تعریف runbookها |
| `runbooks/__init__.py` | Docs | راهنما/package runbooks | توسعه‌دهنده | runbooks/* | Docs | تعریف runbookها |
| `runbooks/app_error_rollback.yml` | Runbook | تعریف عملیات allow-listed و verification/rollback | Runbook registry | execution policy | Runtime data | نباید arbitrary command باشد |
| `runbooks/infrastructure_observation.yml` | Runbook | تعریف عملیات allow-listed و verification/rollback | Runbook registry | execution policy | Runtime data | نباید arbitrary command باشد |
| `runbooks/kubernetes_health.yml` | Runbook | تعریف عملیات allow-listed و verification/rollback | Runbook registry | execution policy | Runtime data | نباید arbitrary command باشد |
| `runbooks/vm_service_recovery.yml` | Runbook | تعریف عملیات allow-listed و verification/rollback | Runbook registry | execution policy | Runtime data | نباید arbitrary command باشد |
| `scripts/__init__.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/add_memory.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/backfill_memory_embeddings.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/check_python_integrity.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/cleanup_repository.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/generate_code_symbols_fa.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/generate_file_index_fa.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/generate_image_attestation.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/mark_stale_memory.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/reconcile_legacy_database.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/render_k8s_release.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/repair_legacy_audit_timestamp.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/trace_incident_logs.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/verify_operational_memory.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `tests/__init__.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_approval_store_db.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_chatbot_db_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_chatbot_llm_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_chatbot_session_management_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_chatbot_tool_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_chatbot_write_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_controlled_connectors.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_dashboard_api.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_e2e_safety.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_health_probes.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_master_api_surface.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_operational_memory_v2_db.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_operator_summary_api.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_rate_limit_db.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_signal_correlation_db.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/operational/__init__.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/operational/run_operational_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/operational/scenarios/core.yaml` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/operational/scenarios/failure_paths.yaml` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/operational/test_harness_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/application_error_spike.json` | Fixture | داده سناریوی تست | scenario tests | Agent/workflow contracts | Test | production path نیست |
| `tests/scenarios/infrastructure_pressure.json` | Fixture | داده سناریوی تست | scenario tests | Agent/workflow contracts | Test | production path نیست |
| `tests/scenarios/kubernetes_health.json` | Fixture | داده سناریوی تست | scenario tests | Agent/workflow contracts | Test | production path نیست |
| `tests/scenarios/test_agent_operational_scenarios.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_database_asset_routing_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_disk_inode_exhaustion_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_failure_injection.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_kubernetes_oom_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_network_asset_routing_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_postgresql_connection_exhaustion_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_vm_asset_routing_acceptance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_governance_security.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_kubernetes_execution_tool.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_logging_redaction.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_route_auth_surface.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_runbook_approval_boundary.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_vm_mcp_security.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_vm_ssh_password_auth.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_architecture_advanced.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_catalog_api.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_completion_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_confidence_sources.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_deterministic_intelligence.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_failure_safety.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_orchestrator_single_path.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_api_workflow_runtime_symbol.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_application_reliability_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_application_trace_peer_context.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_approval_api_transitions.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_approval_binding.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_approval_store_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_asset_enrichment_flow.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_asset_identity_routing.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_audit_flush.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_base_orchestrator_decision_binding.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_benchmark_hardening_2026.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_centralized_config.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_change_correlation_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_auth_api.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_conversation_policy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_error_taxonomy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_frontend_security.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_kubernetes_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_memory_learning.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_preconfirm_guard.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_reliable_service.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_response_redaction.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_stop_regression.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_stream_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_summary_completion_repair.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_tools.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_chatbot_user_message_copy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_cognia_client.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_cognia_only_rag_architecture.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_cognia_orchestrator_status.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_cognia_rag_service.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_cognia_scope_guard.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_container_image_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_context_policy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_agent_layer_compat.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_approval_actions.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_control_center.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_javascript_syntax.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_database_reliability_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dependency_causal_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_direct_execution_runtime_guard.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dotin_general_chatbot_llm.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dual_logging.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_elastic_anomaly_ingestion.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_evaluator.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_evaluator_live_evidence_binding.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_execution_approval_propagation.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_execution_policy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_execution_tool_policy_errors.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_health_readiness_mcp.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_http_transport_policy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_idempotency.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_identity_reliability_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_incident_operational_finalization.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_incident_remediation_binding.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_incident_repository_json.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_incident_resource_migration_guard.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_incident_rid_logging.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_infrastructure_use_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_internal_api_key_role.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_jenkins_mcp_client.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_jsonb_persistence_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_knowledge_topology_execution_gate.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_knowledge_topology_resolution.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_knowledge_topology_url_normalization.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_kubernetes_diagnostic_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_kubernetes_network_policy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_kubernetes_readonly_evidence.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_kubernetes_resource_analyzers.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_latency_observability.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_mcp_external_boundary.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_mcp_server_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_memory_negative_writeback.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_memory_retrieval_query.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_messaging_reliability_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_migration_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_multi_source_signal_reasoning.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_network_reliability_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_oidc_auth.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_operational_agents.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_operational_memory_v2.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_operational_resilience_regressions.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_operator_summary.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_production_fail_closed.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_production_hardening_batch.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_prometheus_alertmanager_ingestion.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_prometheus_mcp_client.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_rag_memory_governance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_rbac.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_rca_auxiliary_memory.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_recovery_readiness_details.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_recovery_readiness_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_release_rendering.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_remediation_planner.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_remediation_runtime_guard.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_api_preflight.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_execution_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_executor.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_learning.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_operational_memory_learning.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_registry_governance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_runtime_guard.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_validation.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_verification_objectives.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runtime_approval_resume.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runtime_error_contracts.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runtime_guard_approval_revocation.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runtime_log_regressions.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_security_incident_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_storage_reliability_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_structured_agent_resilience.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_triage_production_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_upstream_mcp_contracts.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_verification_gate.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_verify_operational_memory.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_config_validation.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_current_cpu_metrics.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_deep_diagnostics.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_diagnostic_evidence.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_execution_boundary.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_guest_engine.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_symptom_verification.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_target_resolution.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_workflow_checkpoint.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_zabbix_mcp_host_header.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_zabbix_recovery_lifecycle.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
