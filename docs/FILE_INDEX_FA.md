# FILE INDEX فارسی — aiops-platform

> این فایل فهرست فایل‌به‌فایل repository است. توضیح معماری و flow در `CODEBASE_GUIDE_FA.md` آمده است.
> این فایل با `scripts/generate_file_index_fa.py` ساخته و در CI کنترل می‌شود.

**تعداد فایل‌های track‌شده و پوشش‌داده‌شده: 254**

| Path | Type | Purpose | Called By | Calls/Depends On | Runtime/Test/Docs | Notes |
|---|---|---|---|---|---|---|
| `.env` | ENV | قرارداد مرکزی تنظیمات runtime و placeholderهای غیرمحرمانه | Settings | Pydantic Settings / همه سرویس‌ها | Runtime | secret واقعی نباید commit شود |
| `.github/workflows/documentation-index.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/image-signing.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/quality.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.github/workflows/repository-hygiene.yml` | CI | Workflow اتوماسیون GitHub Actions | GitHub Actions | repo/tests/deployment | CI | کیفیت، hygiene یا supply chain |
| `.gitignore` | Git | قواعد عدم track فایل‌های generated/local | Git | repository hygiene | Tooling | رفتار runtime ندارد |
| `FINAL_ACCEPTANCE_REPORT.md` | Report | گزارش acceptance بر پایه evidence | تیم | MASTER و tests | Docs | جای MASTER را نمی‌گیرد |
| `MASTER.md` | SSoT | قرارداد معماری، Requirementها و Acceptance اصلی پروژه | تیم و CI | کل معماری | Docs | Single Source of Truth |
| `agents/README.md` | Docs | راهنمای Agent layer و نقش Agentها | توسعه‌دهنده | agents/* | Docs | مرجع لایه Agent |
| `agents/__init__.py` | Python | تعریف package لایه Agent | Python imports | agents/* | Runtime | package marker |
| `agents/application/__init__.py` | Python | Agent تخصصی application برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/change/__init__.py` | Python | Agent تخصصی change برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/database/__init__.py` | Python | Agent تخصصی database برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/dependency/__init__.py` | Python | Agent تخصصی dependency برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/identity/__init__.py` | Python | Agent تخصصی identity برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/infrastructure/__init__.py` | Python | Agent تخصصی infrastructure برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/kubernetes/__init__.py` | Python | Agent تخصصی kubernetes برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/messaging/__init__.py` | Python | Agent تخصصی messaging برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/network/__init__.py` | Python | Agent تخصصی network برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/recovery/__init__.py` | Python | Agent تخصصی recovery برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/security/__init__.py` | Python | Agent تخصصی security برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/shared/a2a_agent.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/base.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/coordinator.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/domain_agent.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/registry.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/shared/telemetry.py` | Python | زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry | Orchestrator/Agentها | domain, LLM, evidence | Runtime | Agent write authority ندارد |
| `agents/storage/__init__.py` | Python | Agent تخصصی storage برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/triage/__init__.py` | Python | Agent تخصصی triage برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `agents/vm/__init__.py` | Python | Agent تخصصی vm برای تحلیل و تولید Finding/Evidence request | Agent registry/orchestrator | agents.shared + evidence | Runtime | تحلیل/پیشنهاد؛ بدون اجرای مستقیم |
| `apps/README.md` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/__init__.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/alert_gateway/__init__.py` | Python | ماژول service لایه application | Runtime | domain/integrations | Runtime | جزء Control Plane |
| `apps/api/__init__.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/a2a.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/agents.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/audit.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/dashboard.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/dashboard_incidents.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/e2e_workflow.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/execution.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/health.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/incident_resources.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/incidents.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/main.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/remediation.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/runbook_execution.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/runbooks.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/signals.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/api/workflow.py` | Python | Route/API سطح کنترل پلتفرم | FastAPI / Dashboard / clients | services, security, database | Runtime | مرز HTTP و RBAC |
| `apps/approval_service/__init__.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/approval_service/postgres.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/approval_service/store.py` | Python | Approval: منطق و persistence Approval با expiry و transition | Workflow/API execution | PostgreSQL/audit | Runtime | security gate قبل از execution |
| `apps/audit_service/__init__.py` | Python | Audit: ثبت، redaction و persistence Audit | boundaryهای حساس | PostgreSQL | Runtime | برای traceability و forensic |
| `apps/audit_service/postgres.py` | Python | Audit: ثبت، redaction و persistence Audit | boundaryهای حساس | PostgreSQL | Runtime | برای traceability و forensic |
| `apps/audit_service/redaction.py` | Python | Audit: ثبت، redaction و persistence Audit | boundaryهای حساس | PostgreSQL | Runtime | برای traceability و forensic |
| `apps/context_service/__init__.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/asset_identity.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/builder.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/evidence_collector.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/normalizer.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/context_service/source_policy.py` | Python | Context: Asset Resolution، Context و Evidence collection | Orchestrator/signal flow | MCP integrations/domain | Runtime | live evidence مرجع عملیات است |
| `apps/database/pgvector_contract.py` | Python | DB: قرارداد/validation pgvector runtime | startup/CI | PostgreSQL | Runtime | schema/dimension guard |
| `apps/database/vector_validation.py` | Python | DB: قرارداد/validation pgvector runtime | startup/CI | PostgreSQL | Runtime | schema/dimension guard |
| `apps/decision_engine/__init__.py` | Python | Decision: تبدیل RCA/evaluation به تصمیم و risk | Orchestrator | evaluation/policy | Runtime | LLM authority نیست |
| `apps/evaluator/__init__.py` | Python | Evaluator: Critic/evaluator gate برای کیفیت RCA | Orchestrator | agent findings/thresholds | Runtime | قبل از decision |
| `apps/evaluator/gate.py` | Python | Evaluator: Critic/evaluator gate برای کیفیت RCA | Orchestrator | agent findings/thresholds | Runtime | قبل از decision |
| `apps/evaluator/thresholds.py` | Python | Evaluator: Critic/evaluator gate برای کیفیت RCA | Orchestrator | agent findings/thresholds | Runtime | قبل از decision |
| `apps/execution_service/__init__.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/idempotency.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/policy.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/base.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/mock_executor.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/registry.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/ssh_vm.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/execution_service/tools/vm_telemetry.py` | Python | Execution: مرز اجرای governed، tool registry، idempotency و policy | API/workflow | Approval/tools/MCP | Runtime | write boundary؛ fail-closed |
| `apps/incident_service/repository.py` | Python | Persistence: Repository durable Incident/Evidence/Finding | signal/workflow/dashboard | SQLAlchemy/PostgreSQL | Runtime | هسته persistence incident |
| `apps/mcp_server/__init__.py` | Python | MCP: MCP server داخلی برای expose ابزارهای کنترل‌شده | MCP clients | provider adapters/security | Runtime | capability boundary |
| `apps/mcp_server/main.py` | Python | MCP: MCP server داخلی برای expose ابزارهای کنترل‌شده | MCP clients | provider adapters/security | Runtime | capability boundary |
| `apps/memory_service/__init__.py` | Python | Memory: Operational Memory retrieval/write-back | Workflow/agents/API | pgvector/embeddings | Runtime | جای live evidence را نمی‌گیرد |
| `apps/orchestrator/a2a_gateway.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/e2e_graph.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/graph.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/guardrails.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/runtime.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/signal_aware.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/orchestrator/workflow_store.py` | Python | Workflow: LangGraph orchestration، routing، resume و collaboration | API/signal gateway | agents/context/decision/approval | Runtime | مسیر E2E durable |
| `apps/rag_service/__init__.py` | Python | RAG: Knowledge RAG با governance و vector retrieval | Workflow/agents/API | pgvector/embedding | Runtime | دانش رسمی، جدا از memory |
| `apps/runbook_service/executor.py` | Python | Runbook: Registry/Executor runbookهای allow-listed | API/execution workflow | domain/runbooks/execution | Runtime | اجرای کنترل‌شده |
| `apps/runbook_service/registry.py` | Python | Runbook: Registry/Executor runbookهای allow-listed | API/execution workflow | domain/runbooks/execution | Runtime | اجرای کنترل‌شده |
| `apps/security/auth.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/security/oidc.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/security/rbac.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/security/token_validator.py` | Python | Security: Authentication، OIDC/JWT و RBAC | FastAPI dependencies | OIDC/config | Runtime | security boundary |
| `apps/signal_gateway/__init__.py` | Python | Signal: ورود، normalization، correlation و dedupe سیگنال | API/webhooks | incident repository/context | Runtime | ابتدای Incident flow |
| `apps/signal_gateway/correlation.py` | Python | Signal: ورود، normalization، correlation و dedupe سیگنال | API/webhooks | incident repository/context | Runtime | ابتدای Incident flow |
| `apps/verification_service/__init__.py` | Python | Verify: Verification مستقل پس از remediation | Workflow/execution | live evidence/audit | Runtime | tool success برابر recovery نیست |
| `dashboards/__init__.py` | Python | package marker dashboard | Python | — | Tooling | رفتار مستقل ندارد |
| `dashboards/agents.html` | HTML | پوسته و layout داشبورد | FastAPI static route | CSS/JS/API | Runtime UI | صفحه اپراتوری |
| `dashboards/approval-actions.css` | CSS | استایل Control Center و کنترل‌های عملیاتی | Browser | HTML classes | Runtime UI | بدون داده fake |
| `dashboards/approval-actions.js` | JS | state، API binding و interaction داشبورد | Browser | /api/v1 endpoints | Runtime UI | action حساس backend-governed است |
| `dashboards/control-center.css` | CSS | استایل Control Center و کنترل‌های عملیاتی | Browser | HTML classes | Runtime UI | بدون داده fake |
| `dashboards/control-center.js` | JS | state، API binding و interaction داشبورد | Browser | /api/v1 endpoints | Runtime UI | action حساس backend-governed است |
| `dashboards/index.html` | HTML | پوسته و layout داشبورد | FastAPI static route | CSS/JS/API | Runtime UI | صفحه اپراتوری |
| `database/__init__.py` | Python | Engine/session factory پایگاه‌داده | repository/storeها | SQLAlchemy/.env | Runtime | اتصال مرکزی PostgreSQL |
| `database/migrations/002_governance_persistence.sql` | SQL | SQL قدیمی/مرجع migration legacy | اپراتور legacy | PostgreSQL | Legacy | روی DB جدید جداگانه اجرا نشود |
| `database/migrations/003_workflow_incident_persistence.sql` | SQL | SQL قدیمی/مرجع migration legacy | اپراتور legacy | PostgreSQL | Legacy | روی DB جدید جداگانه اجرا نشود |
| `database/migrations/README` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/alembic.ini` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/env.py` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/script.py.mako` | Alembic | تنظیمات و runtime migration | Alembic | SQLAlchemy/.env | DB | زیرساخت migration |
| `database/migrations/versions/0ee48995b0c1_add_rag_and_memory_tables.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/34ec6bd70cb3_initial_migration_incident_evidence_.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/bce19e0dbd2d_fix_embedding_column_type.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/f1a2b3c4d5e6_add_operational_persistence.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `database/migrations/versions/f2b3c4d5e6f7_approval_consumed_state.py` | Alembic | Migration نسخه‌دار schema PostgreSQL | Alembic/CI | domain models/pgvector | DB | canonical migration chain |
| `deployment/__init__.py` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/docker/offline/ARTIFACT_MANIFEST.md` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/docker/offline/Dockerfile` | Docker | ساخت image آفلاین پلتفرم | Docker/CI | requirements/repo | Deploy | برای شبکه محدود |
| `deployment/docker/offline/README.md` | Docs | راهنما یا artifact manifest استقرار | اپراتور | deployment files | Deploy | offline/supply-chain |
| `deployment/kubernetes/aiops-platform.yaml` | K8s | Manifest/نمونه config استقرار | Kubernetes/OpenShift | image/.env/secrets | Deploy | runtime deployment |
| `deployment/kubernetes/configuration.example.yaml` | K8s | Manifest/نمونه config استقرار | Kubernetes/OpenShift | image/.env/secrets | Deploy | runtime deployment |
| `docs/BENCHMARK_2026.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CODEBASE_GUIDE_FA.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/CONFIGURATION.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/FILE_INDEX_FA.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/MULTI_SOURCE_REASONING.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/NEXT_TASK.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/PRODUCTION_ACCEPTANCE_MATRIX.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/PRODUCTION_HARDENING_WIP.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/PROJECT_STATE.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/UPSTREAM_MCP_PROVIDERS.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/VM_REMEDIATION.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
| `docs/__init__.py` | Python | package marker docs | Python | — | Docs | رفتار runtime ندارد |
| `docs/adr/ADR-017-UPSTREAM-MCP-PROVIDERS.md` | Docs | مستند معماری/عملیات/وضعیت پروژه | تیم | کد و MASTER | Docs | SSoT نیست مگر MASTER root |
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
| `domain/contracts/retry.py` | Python | Contract مشترک config/context/error/log/retry/rate-limit | کل runtime | Pydantic/FastAPI | Runtime | قرارداد زیرساختی |
| `domain/hypothesis.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/idempotency.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/incident_context.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/incident_transition.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/models.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/runbook.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/runbook_validation.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/schemas.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `domain/verification_gate.py` | Python | مدل/Schema/قواعد دامنه AIOps | apps/* | Pydantic/SQLAlchemy | Runtime | مدل مشترک لایه‌ها |
| `integrations/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/base.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/elasticsearch/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/elasticsearch/client.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/elasticsearch/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
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
| `integrations/vm/ssh_connector.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/__init__.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/client.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/connector.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/evidence.py` | Python | Adapter provider/read-only integration | MCP server/test helper | external API/.env | Runtime/Helper | Control Plane production ترجیحاً MCP |
| `integrations/zabbix/mcp_client.py` | Python | MCP client برای ارتباط governed با ابزار بیرونی | Evidence/Tool layer | MCP transport/.env | Runtime | canonical external-tool path |
| `knowledge/__init__.py` | Python | Contract/helper لایه Knowledge RAG | RAG service | metadata/ACL | Runtime | دانش رسمی governed |
| `knowledge/retrieval_contract.py` | Python | Contract/helper لایه Knowledge RAG | RAG service | metadata/ACL | Runtime | دانش رسمی governed |
| `memory/__init__.py` | Python | Namespace/contract Operational Memory | Memory service | pgvector | Runtime | تجربه incidentهای قبلی |
| `memory/namespace.py` | Python | Namespace/contract Operational Memory | Memory service | pgvector | Runtime | تجربه incidentهای قبلی |
| `requirements.txt` | Deps | فهرست dependencyهای Python | pip/CI/Docker | runtime packages | Build | ورودی نصب dependency |
| `runbooks/README.md` | Docs | راهنما/package runbooks | توسعه‌دهنده | runbooks/* | Docs | تعریف runbookها |
| `runbooks/__init__.py` | Docs | راهنما/package runbooks | توسعه‌دهنده | runbooks/* | Docs | تعریف runbookها |
| `runbooks/app_error_rollback.yml` | Runbook | تعریف عملیات allow-listed و verification/rollback | Runbook registry | execution policy | Runtime data | نباید arbitrary command باشد |
| `runbooks/infrastructure_observation.yml` | Runbook | تعریف عملیات allow-listed و verification/rollback | Runbook registry | execution policy | Runtime data | نباید arbitrary command باشد |
| `runbooks/kubernetes_health.yml` | Runbook | تعریف عملیات allow-listed و verification/rollback | Runbook registry | execution policy | Runtime data | نباید arbitrary command باشد |
| `scripts/__init__.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/add_knowledge.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/add_memory.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/check_python_integrity.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/cleanup_repository.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/generate_file_index_fa.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `scripts/generate_image_attestation.py` | Python | ابزار maintenance/validation/seed/build | Developer/CI | repo/database | Tooling | مسیر اپراتوری کمکی |
| `tests/__init__.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_controlled_connectors.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_dashboard_api.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_e2e_safety.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_health_probes.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_master_api_surface.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/integration/test_signal_correlation_db.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/application_error_spike.json` | Fixture | داده سناریوی تست | scenario tests | Agent/workflow contracts | Test | production path نیست |
| `tests/scenarios/infrastructure_pressure.json` | Fixture | داده سناریوی تست | scenario tests | Agent/workflow contracts | Test | production path نیست |
| `tests/scenarios/kubernetes_health.json` | Fixture | داده سناریوی تست | scenario tests | Agent/workflow contracts | Test | production path نیست |
| `tests/scenarios/test_agent_operational_scenarios.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/scenarios/test_failure_injection.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/security/test_governance_security.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_architecture_advanced.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_completion_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_confidence_sources.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_failure_safety.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_agent_orchestrator_single_path.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_approval_api_transitions.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_approval_binding.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_approval_store_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_asset_enrichment_flow.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_asset_identity_routing.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_audit_flush.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_benchmark_hardening_2026.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_centralized_config.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_context_policy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_approval_actions.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_control_center.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dashboard_javascript_syntax.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_dual_logging.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_evaluator.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_execution_approval_propagation.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_execution_policy.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_idempotency.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_internal_api_key_role.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_jsonb_persistence_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_kubernetes_readonly_evidence.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_mcp_external_boundary.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_mcp_server_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_migration_contract.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_multi_source_signal_reasoning.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_oidc_auth.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_operational_agents.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_production_fail_closed.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_production_hardening_batch.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_rag_memory_governance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_rbac.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_executor.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_registry_governance.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runbook_validation.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_runtime_approval_resume.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_upstream_mcp_contracts.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_verification_gate.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_vm_execution_boundary.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
| `tests/unit/test_workflow_checkpoint.py` | Test | تست regression/contract برای بخش متناظر | pytest/CI | کد production | Test | شواهد repository-level |
