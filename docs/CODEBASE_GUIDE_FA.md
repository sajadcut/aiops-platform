# راهنمای فارسی Codebase پروژه aiops-platform

این سند برای خواندن **کد واقعی** پروژه است. `MASTER.md` همچنان Single Source of Truth معماری و Requirementهاست؛ این فایل فقط توضیح می‌دهد هر بخش از repository چه نقشی دارد و جریان اجرا چگونه بین فایل‌ها حرکت می‌کند.

## 1) نقشه کل repository

```text
.env                         تنظیمات مرکزی runtime
MASTER.md                    قرارداد نهایی معماری و acceptance
FINAL_ACCEPTANCE_REPORT.md   گزارش وضعیت مبتنی بر evidence
agents/                      Agentهای تخصصی و زیرساخت همکاری آنها
apps/                        application/control-plane services و API
integrations/                adapterها و MCP clientهای ابزارهای خارجی
domain/                      مدل‌ها، schemaها و contractهای مشترک
database/                    engine/session و Alembic migrations
knowledge/                   contract دانش رسمی/RAG
memory/                      namespace و contract حافظه عملیاتی
runbooks/                    runbookهای governed و allow-listed
dashboards/                  UI اپراتوری AIOps Control Center
deployment/                  Docker offline و Kubernetes/OpenShift manifests
scripts/                     ابزارهای validation/seed/maintenance
tests/                       unit/integration/scenario/security evidence
.github/workflows/           CI، hygiene و supply-chain automation
docs/                        ADR، runbook و توضیحات تکمیلی معماری
```

## 2) Flow اصلی AIOps و فایل‌های درگیر

```text
Alert / Signal
  -> Normalization / Correlation
  -> Asset Resolution
  -> Context
  -> Live Evidence
  -> Knowledge RAG + Operational Memory
  -> Triage
  -> Specialist Agents
  -> Multi-Agent Coordination / RCA
  -> Evaluator
  -> Decision / Policy
  -> Approval
  -> Durable Checkpoint
  -> Execution
  -> Verification
  -> Audit
  -> Memory Write-back
  -> Dashboard
```

مسیر ورودی عمدتاً از `apps/api/signals.py` و `apps/signal_gateway/*` شروع می‌شود. Signal Gateway منبع را به یک Incident canonical تبدیل می‌کند، correlation/deduplication را اعمال می‌کند و از repository حادثه استفاده می‌کند. سپس `apps/orchestrator/e2e_graph.py` و `apps/orchestrator/runtime.py` state را بین nodeها جابه‌جا می‌کنند. Context و Evidence از `apps/context_service/*` و MCP clientهای `integrations/*/mcp_client.py` می‌آیند. Agentها در `agents/*` فقط تحلیل و Finding تولید می‌کنند. تصمیم و evaluator در `apps/evaluator/*` و `apps/decision_engine/*` هستند. write action فقط از execution boundary عبور می‌کند و approval، policy، allow-list و idempotency را رعایت می‌کند. نتیجه بعد از execution توسط `apps/verification_service` مستقل verify و سپس audit/memory ثبت می‌شود.

## 3) پوشه agents/

### agents/shared/base.py
هسته contract مشترک Agentهاست. مسئول جمع‌کردن evidence قابل استفاده، اعمال محدودیت کیفیت/تعداد evidence، صدا زدن LLM provider، تبدیل پاسخ به ساختار قابل‌اعتماد و محاسبه confidence است. Agent از این لایه برای reasoning استفاده می‌کند، اما حق اجرای write action ندارد.

### agents/shared/domain_agent.py
یک پیاده‌سازی reusable برای Agentهای دامنه‌ای است. به Agent اجازه می‌دهد با vocabulary و evidence typeهای تخصصی خودش Finding بسازد، بدون اینکه orchestration یا security boundary را دوباره پیاده کند.

### agents/shared/coordinator.py
Findingهای چند Agent را کنار هم می‌گذارد، disagreement و missing evidence را لحاظ می‌کند، hypothesisها را merge/score می‌کند و یک RCA هماهنگ می‌سازد. هدف این است که خروجی یک Agent به‌تنهایی authority نباشد.

### agents/shared/registry.py
Catalog/registry Agentهاست. orchestrator از این registry برای پیدا کردن Agentهای فعال و capability آنها استفاده می‌کند.

### agents/shared/a2a_agent.py و apps/orchestrator/a2a_gateway.py
مسیر Agent-to-Agent است. برای collaboration کنترل‌شده بین Agentها استفاده می‌شود؛ targetهای A2A و HTTPS از config محدود می‌شوند.

### agents/shared/telemetry.py
metric/telemetry خود Agent layer را تولید می‌کند تا invocation، confidence و خطاهای Agent قابل مشاهده باشند.

### Agentهای تخصصی

- `agents/application/__init__.py`: خطاهای HTTP، latency، exception، dependency و رفتار application را تحلیل می‌کند.
- `agents/infrastructure/__init__.py`: CPU، memory، load، host pressure و زیرساخت را بررسی می‌کند.
- `agents/kubernetes/__init__.py`: Pod/Node/Event/CrashLoop/OOM/Probe/Rollout را تحلیل می‌کند.
- `agents/vm/__init__.py`: Linux/Windows VM evidence، service/process و telemetry را تحلیل می‌کند.
- `agents/security/__init__.py`: evidence امنیتی و رفتار مشکوک را تحلیل می‌کند؛ write authority ندارد.
- `agents/database/__init__.py`: symptomهای database مانند saturation/connection/latency را بررسی می‌کند.
- `agents/network/__init__.py`: failureهای شبکه و connectivity را در RCA وارد می‌کند.
- `agents/storage/__init__.py`: capacity/IO/storage pressure را پوشش می‌دهد.
- `agents/identity/__init__.py`: authentication/identity symptomها را بررسی می‌کند.
- `agents/change/__init__.py`: change/rollout/recent deployment را به عنوان علت احتمالی correlate می‌کند.
- `agents/dependency/__init__.py`: upstream/downstream dependency failure را بررسی می‌کند.
- `agents/messaging/__init__.py`: queue/broker/messaging symptomها را تحلیل می‌کند.
- `agents/recovery/__init__.py`: recovery-oriented recommendation می‌سازد؛ execution همچنان بیرون Agent است.
- `agents/triage/__init__.py`: severity/domain اولیه و Agentهای مناسب را تعیین می‌کند.

Agentها به شکل مستقیم credential write ابزار بیرونی دریافت نمی‌کنند. evidence باید از لایه integration/context بیاید و اجرای واقعی تنها از Execution Boundary انجام شود.

## 4) apps/ — application layer

### apps/api/main.py
نقطه startup FastAPI است. routerها، CORS، logging، static dashboard، startup validation، production fail-closed checks، pgvector validation و registration ابزارهای runtime در این فایل به هم وصل می‌شوند. اگر production config ناامن باشد startup باید fail شود.

### apps/api/signals.py
API ورود signal. payload را به Signal Gateway می‌دهد و authentication/rate limit را از security contract می‌گیرد.

### apps/api/incidents.py و incident_resources.py
`incidents.py` عملیات analyze/create flow را expose می‌کند. `incident_resources.py` context/evidence/knowledge/memory/plan/verification/audit/lifecycle یک Incident را برای Dashboard و اپراتور می‌خواند.

### apps/api/execution.py
یکی از حساس‌ترین فایل‌هاست. Approval Request، approve/reject و direct governed execution را expose می‌کند. Approval به incident/action/tool/target bind می‌شود، expiry و role بررسی می‌شود و قبل از crossing execution boundary فقط یک بار `consumed` می‌شود.

### apps/api/remediation.py و runbook_execution.py
مسیر remediation/runbook actionهای governed. Dry-run از execution واقعی جداست و backend باید authorization را enforce کند.

### apps/api/dashboard*.py
Aggregationهای مخصوص UI را از state durable PostgreSQL می‌سازند. داده fake نباید جای داده واقعی را بگیرد.

### apps/context_service/asset_identity.py
Asset/Service identity را از signal و evidence می‌سازد. این بخش تعیین می‌کند alert مربوط به VM، Kubernetes workload، service یا asset دیگری است و routing evidence/Agent را هدایت می‌کند.

### apps/context_service/evidence_collector.py
Evidence چند منبع را جمع می‌کند. تفاوت مهم: source failure با «healthy/zero anomaly» یکی نیست. نتیجه provider باید provenance و availability داشته باشد.

### apps/incident_service/repository.py
Persistence canonical Incident، Evidence و Finding. transaction/locking مربوط به correlation و durable state در این لایه قرار می‌گیرد.

### apps/orchestrator/e2e_graph.py
تعریف workflow اصلی LangGraph و node/routingها. state از context تا verification/memory پیش می‌رود. این فایل باید evaluator gate، approval pause، failure route و عدم bypass execution را حفظ کند.

### apps/orchestrator/runtime.py
اجرای graph، pause/resume و interaction با checkpoint durable را مدیریت می‌کند. بعد از restart باید state از PostgreSQL قابل بازیابی باشد.

### apps/orchestrator/workflow_store.py
state/checkpoint workflow را در PostgreSQL می‌خواند/می‌نویسد؛ برای restart durability و optimistic versioning مهم است.

### apps/orchestrator/signal_aware.py
Signal type/source/asset را در routing reasoning وارد می‌کند و cross-source investigation را هدایت می‌کند.

### apps/evaluator/gate.py
کیفیت reasoning را قبل از Decision بررسی می‌کند: evidence coverage، confidence، disagreement و thresholdها. evaluator نباید صرفاً PASS صوری تولید کند.

### apps/decision_engine/__init__.py
RCA و evaluator را به Decision/Risk/Approval requirement تبدیل می‌کند. LLM recommendation در اینجا هنوز authority اجرایی نیست.

### apps/approval_service/postgres.py
Approval durable در PostgreSQL. transition فقط از `pending` به `approved/rejected`، expiry و one-time consume را enforce می‌کند. race-safe update برای جلوگیری از دو approval همزمان مهم است.

### apps/execution_service/
- `__init__.py`: مدل request/result و coordinator اجرای ابزار.
- `policy.py`: تصمیم policy برای action/risk.
- `idempotency.py`: جلوگیری از اجرای دوباره همان action.
- `tools/registry.py`: allow-listed tools/capabilities.
- `tools/base.py`: contract ابزار اجرایی.
- `tools/ssh_vm.py`: wrapper governed برای VM remediation از طریق VM MCP connector.
- `tools/vm_telemetry.py`: read-only VM telemetry tool.
- `tools/mock_executor.py`: فقط non-production/test path؛ production نباید به آن تکیه کند.

### apps/verification_service/__init__.py
بعد از execution دوباره evidence مستقل می‌گیرد و success criteria را بررسی می‌کند. موفق بودن tool call به تنهایی به معنی recovery نیست.

### apps/audit_service/
هر تصمیم حساس، approval، execution و verification باید audit durable داشته باشد. `redaction.py` اطلاعات حساس را قبل از persistence/logging پاک می‌کند.

### apps/rag_service و apps/memory_service
RAG برای دانش رسمی governed و Operational Memory برای تجربه incidentهای قبلی هستند. هر دو vector retrieval دارند، ولی memory نباید current live evidence یا policy را override کند.

## 5) integrations/ و MCP

`integrations/mcp_client.py` transport عمومی MCP، timeout/TLS/auth و tool discovery/call را مدیریت می‌کند.

### Zabbix
`integrations/zabbix/mcp_client.py` Control Plane را به Zabbix MCP Server متصل می‌کند. endpoint از `ZABBIX_MCP_URL` می‌آید. connector/client مستقیم Zabbix برای provider-side helper/test وجود دارد؛ مسیر production Control Plane باید MCP باشد.

### Elastic
`integrations/elasticsearch/mcp_client.py` به Kibana Elastic Agent Builder MCP (`/api/agent_builder/mcp`) وصل می‌شود. namespace/index pattern از `.env` می‌آید. ES|QL evidence باید provenance داشته باشد.

### Prometheus
`integrations/prometheus/mcp_client.py` metric query/evidence را از Prometheus MCP می‌گیرد. نبود metric به علت MCP failure نباید healthy تفسیر شود.

### Kubernetes
`integrations/kubernetes/mcp_client.py` مسیر canonical Control Plane برای K8s tooling است. client مستقیم Kubernetes helper/server-side است و production Control Plane نباید token native را به Agent بدهد.

### VM
`integrations/vm/mcp_client.py` telemetry/remediation را به Edge/VM MCP منتقل می‌کند. `ssh_connector.py` connector native است که باید پشت MCP/tool boundary بماند، نه داخل Agent reasoning.

### LLM
`integrations/llm/base.py` contract provider؛ `openai_compatible.py` adapter HTTP؛ `mock_provider.py` فقط non-production. LLM evidence را تحلیل می‌کند ولی اجازه approve یا execute ندارد.

## 6) database/ و مدل داده

`database/__init__.py` engine و `AsyncSessionLocal` را از `DATABASE_URL` می‌سازد.

مدل‌های اصلی در `domain/models.py`:

- `incidents`: هویت و lifecycle حادثه.
- `evidences`: factهای live/provider با FK به Incident.
- `findings`: تحلیل Agent با reference به evidence.
- `knowledge_documents`: RAG رسمی با metadata و `vector(1536)`.
- `memory_entries`: تجربه عملیاتی با embedding و outcome.

Migration `f1a2b3c4d5e6` persistenceهای `approvals`, `audit_events`, `runbooks`, `workflow_checkpoints` را اضافه می‌کند. Migration `f2b3c4d5e6f7` status `consumed` را برای anti-replay approval اضافه می‌کند.

فایل‌های SQL `002_*.sql` و `003_*.sql` legacy هستند و برای دیتابیس جدید نباید جدا از Alembic canonical اجرا شوند.

JSON/JSONB برای stateهای heterogeneous مثل metadata، checkpoint، runbook steps و evidence payload استفاده می‌شود. pgvector برای similarity retrieval دانش و memory است؛ dimension runtime از config validate می‌شود.

## 7) Security boundaries

1. **Authentication**: `apps/security/auth.py` OIDC Bearer یا Internal API Key را resolve می‌کند.
2. **OIDC/JWT**: `token_validator.py` issuer/audience/JWKS را validate می‌کند.
3. **RBAC**: `rbac.py` role -> permission mapping است؛ operator و SRE قدرت یکسان ندارند.
4. **LLM boundary**: Agent/LLM فقط recommendation/Finding می‌دهد.
5. **Approval boundary**: approval action به incident/tool/target bind و expire/consume می‌شود.
6. **Execution boundary**: فقط tool registry و policy اجازه crossing write path می‌دهند.
7. **Verification boundary**: success مستقل از executor دوباره اثبات می‌شود.
8. **Audit**: actionهای حساس durable و redacted ثبت می‌شوند.
9. **Production startup**: config ناامن باید startup را fail کند.

## 8) Dashboard

### dashboards/index.html
Shell اصلی UI: sidebar، Command Center، Incident Workbench، Services، Agents، MCP و Audit views.

### dashboards/control-center.js
state ساده browser (`S`) را نگه می‌دارد؛ API key، summary، incidents، services، health، agent catalog و selected incident را مدیریت می‌کند. Incident detail از endpointهای context/evidence/lifecycle/verification می‌آید. loading/empty/error stateها واقعی هستند و fake data نباید inject شود.

### dashboards/approval-actions.js
تب Decision را با Approval واقعی lifecycle enrich می‌کند. Approve endpoint backend را صدا می‌زند؛ Reject reason اجباری دارد. Approve خودش execute نمی‌کند.

### CSS
`control-center.css` Design System اصلی و `approval-actions.css` کنترل‌های governance را style می‌کند.

## 9) .env — گروه‌های تنظیمات

- App: `APP_NAME`, `APP_VERSION`, `APP_ENV`, `HOST`, `PORT`.
- Database: URL، pool و Alembic URL.
- LLM/Embedding: provider/model/base URL/API key/dimension/timeout.
- Agent: evidence limits، confidence، parallelism، timeout، A2A.
- Signal correlation: window و candidate limit.
- Logging: console/text/json file، path، rotation و retention.
- API security: internal API key/role، rate limit، CORS، approval TTL.
- MCP: protocol/TLS/bearer/mTLS/timeout.
- Provider MCP: Zabbix، Elastic Agent Builder، Prometheus، Kubernetes، VM.
- Native provider settings: فقط server-side helper/test/migration مسیرها.
- OIDC و deployment registry.

تنظیم runtime باید از `.env`/environment injection بیاید. secret production نباید در Git قرار بگیرد.

## 10) Runbooks

فایل‌های YAML در `runbooks/` definitionهای governed هستند. registry آنها را validate می‌کند. action باید allow-listed، risk-aware، timeoutدار و در صورت تعریف rollback/verification داشته باشد. arbitrary shell/PowerShell نباید از Agent آزادانه عبور کند.

## 11) Deployment و CI

`deployment/docker/offline/Dockerfile` image مناسب محیط offline/restricted می‌سازد. `deployment/kubernetes/aiops-platform.yaml` deployment/service/probe/config injection را تعریف می‌کند. `configuration.example.yaml` نمونه Kubernetes config است و جای `.env` canonical runtime را نمی‌گیرد.

`quality.yml` syntax، imports، full tests، PostgreSQL+pgvector migration و downgrade/rebuild را اجرا می‌کند. `repository-hygiene.yml` artifactهای generated/secretهای واضح را کنترل می‌کند. `image-signing.yml` مسیر supply-chain signing/attestation را پوشش می‌دهد.

## 12) Tests چگونه خوانده شوند

- `tests/unit/`: contract یک component یا boundary.
- `tests/integration/`: چند component واقعی‌تر مثل API/DB/connectors.
- `tests/scenarios/`: سناریوی عملیاتی E2E/failure.
- `tests/security/`: invariantهای governance/security.

نام هر test عمداً به component متناظر اشاره می‌کند؛ `FILE_INDEX_FA.md` برای همه آنها ردیف دارد.

## 13) Dependency map ساده

```text
FastAPI API
  -> Signal Gateway / Incident Repository
  -> Orchestrator (LangGraph)
       -> Context + Asset Identity
       -> MCP Evidence Clients
       -> Knowledge RAG / Operational Memory
       -> Agent Registry + Specialist Agents
       -> Coordinator / Evaluator
       -> Decision Engine
       -> Approval Store
       -> Execution Service / Tool Registry
       -> Verification Service
       -> Audit + Memory Write-back
  -> PostgreSQL + pgvector
  -> Dashboard read/action APIs
```

## 14) اگر فایل‌های اصلی حذف شوند چه می‌شکند؟

- حذف `apps/api/main.py`: HTTP API و startup وجود ندارد.
- حذف `apps/orchestrator/e2e_graph.py`: مسیر E2E Incident از هم می‌پاشد.
- حذف `apps/context_service/evidence_collector.py`: reasoning بدون live cross-source evidence می‌شود.
- حذف `agents/shared/base.py`: contract مشترک Agent و LLM/evidence processing می‌شکند.
- حذف `apps/approval_service/postgres.py`: approval durable/expiry/anti-replay از بین می‌رود.
- حذف `apps/execution_service/*`: write boundary و tool governance وجود ندارد.
- حذف `apps/verification_service`: platform نمی‌تواند recovery را مستقل اثبات کند.
- حذف `database/migrations/*`: schema reproducible و CI DB acceptance از بین می‌رود.
- حذف `domain/contracts/config.py`: contract typed تنظیمات مرکزی شکسته می‌شود.
- حذف `integrations/mcp_client.py`: transport canonical ابزارهای بیرونی از Control Plane می‌شکند.
- حذف `dashboards/control-center.js`: UI فقط shell بدون داده/interaction می‌شود.

## 15) Glossary ساده

- **Signal**: یک alert/anomaly/event خام از observability.
- **Incident**: واحد durable بررسی و پاسخ به یک failure.
- **Evidence**: fact قابل استناد از سیستم واقعی؛ log/metric/event/trace/alert.
- **Finding**: نتیجه تحلیل Agent روی Evidence.
- **RCA**: تحلیل علت ریشه‌ای.
- **RAG**: بازیابی دانش رسمی مرتبط برای کمک به reasoning.
- **Operational Memory**: تجربه incidentهای قبلی و outcome آنها.
- **MCP**: transport/tool protocol کنترل‌شده بین Control Plane و ابزارهای بیرونی.
- **Evaluator**: critic که کیفیت reasoning را قبل از Decision بررسی می‌کند.
- **Policy**: قواعد deterministic برای مجاز/غیرمجاز بودن action.
- **Approval**: مجوز انسانی/حاکمیتی bind شده به action مشخص.
- **Execution Boundary**: تنها مرزی که write واقعی را اجازه می‌دهد.
- **Verification**: بررسی مستقل بعد از اجرا برای اثبات recovery.
- **Checkpoint**: state durable workflow برای resume بعد از pause/restart.
- **Idempotency**: جلوگیری از اثر تکراری اجرای یک درخواست.
- **Fail-closed**: هنگام ابهام/خرابی اجازه action خطرناک داده نمی‌شود.

## 16) چگونه یک فایل را بخوانیم؟

برای هر path ابتدا ردیف آن را در `FILE_INDEX_FA.md` پیدا کن. بعد importهای بالای فایل را ببین تا dependencyها مشخص شوند. برای فایل‌های runtime، مشخص کن آیا read-only است یا write boundary. در workflowها به `state` و transitionها توجه کن. در integrationها provenance/failure behavior مهم است. در Agentها evidence input و Finding output مهم است، نه صرفاً prompt. در testها assertion را به invariant production متناظر وصل کن.
