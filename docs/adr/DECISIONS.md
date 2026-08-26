# AI Ops NeoBankingOperation Platform — DECISIONS

این فایل خلاصه تصمیم‌های معماری و قراردادی پروژه است. تصمیم قطعی باید اینجا ثبت شود؛ موضوعات باز نباید به‌عنوان تصمیم قطعی استفاده شوند.

## ADR-001 — AI Core

**Status:** ACCEPTED

**Decision:** Python + LangGraph هسته Orchestration و Agentic Workflow است.

**Rationale:** State, routing, parallelization, tool calling, evaluation و کنترل workflow نیاز اصلی پروژه‌اند.

**Constraint:** انتقال هسته AI به .NET بدون ADR جدید مجاز نیست.

---

## ADR-002 — Enterprise .NET Boundary

**Status:** ACCEPTED

**Decision:** .NET فقط در صورت نیاز برای Integration/API یا سرویس‌های سازمانی استفاده می‌شود و هسته AI نیست.

**Constraint:** سرویس .NET نباید LangGraph را به‌عنوان هسته پروژه جایگزین کند مگر با ADR جدید.

---

## ADR-003 — Primary Persistence

**Status:** ACCEPTED

**Decision:** PostgreSQL دیتابیس اصلی Persistence پروژه است.

**Constraint:** SQL Server انتخاب Persistence اصلی این پروژه نیست.

---

## ADR-004 — Vector Layer

**Status:** ACCEPTED

**Decision:** pgvector به‌عنوان Vector Search Layer اصلی و یکپارچه با PostgreSQL انتخاب می‌شود.

**Rationale:** کاهش پیچیدگی زیرساخت، نگهداری relational + vector data در یک سیستم، مناسب برای MVP و Offline Production.

**Constraint:** اضافه‌کردن Vector DB مستقل مانند Qdrant/Weaviate/Milvus نیازمند نیاز عملیاتی اثبات‌شده یا ADR جدید است.

---

## ADR-005 — RAG Architecture

**Status:** ACCEPTED

**Decision:** Knowledge RAG از PostgreSQL + pgvector و یک abstraction لایه بازیابی استفاده می‌کند.

**Purpose:** بازیابی Runbook، Architecture Docs، Procedures و Knowledge تأییدشده.

**Critical Rule:** RAG منبع حقیقت برای Live Production Evidence نیست.

---

## ADR-006 — Operational Memory

**Status:** ACCEPTED

**Decision:** Operational Memory از ابتدا در معماری تعریف می‌شود و می‌تواند با PostgreSQL + pgvector پیاده‌سازی شود.

**Memory content:** incident patterns، symptoms، hypotheses، actions، verification، outcomes و reuse metadata.

**Critical Rule:** Memory منبع اصلی Evidence زنده Production نیست و فقط تجربه کمکی ارائه می‌کند.

---

## ADR-007 — Mem0 Boundary

**Status:** ACCEPTED AS OPTIONAL

**Decision:** Mem0 در صورت نیاز قابل استفاده است، اما dependency اجباری پروژه نیست.

**Rule:** هر integration با Mem0 فقط از طریق Memory abstraction / adapter انجام شود.

**Forbidden:** قرار دادن Mem0-specific types یا API contracts در Domain Core.

---

## ADR-008 — Execution Boundary

**Status:** ACCEPTED

**Decision:** Agentها حق تغییر مستقیم سیستم را ندارند. تنها Execution Service / approved Tool boundary مجاز به write action است.

**Required controls:** allowlist، scope، environment، risk، timeout، approval و audit.

---

## ADR-009 — Evidence First

**Status:** ACCEPTED

**Decision:** RCA و تصمیم عملیاتی باید به Evidence قابل ارجاع متصل باشند.

**Evidence priority:** Live/authoritative operational evidence بر RAG و Memory مقدم است.

---

## ADR-010 — Automation Levels

**Status:** ACCEPTED

**Decision:** حرکت اتوماسیون به‌صورت L0 Observe → L1 Recommend → L2 Approval → L3 Guarded Auto انجام می‌شود.

**Constraint:** Production Auto-execute پیش‌فرض Deny است و فقط برای Runbookهای کم‌ریسک و Policy-approved مجاز می‌شود.

---

## ADR-011 — LLM Abstraction

**Status:** ACCEPTED

**Decision:** تمام Model/LLM integrationها از Adapter/Gateway عبور می‌کنند.

**Constraint:** Agent نباید مستقیم به SDK یا Vendor-specific model API وابسته باشد.

---

## ADR-012 — Modular Agents

**Status:** ACCEPTED

**Decision:** Agentها modular و contract-based هستند و می‌توان Agent جدید را بدون بازنویسی کل معماری اضافه کرد.

**Required contract:** input/state، tools، structured output، evidence references، confidence و policy constraints.

---

## ADR-013 — MVP Scope

**Status:** ACCEPTED

**Decision:** MVP باید یک حلقه کامل و قابل اعتماد را اثبات کند، نه کل دیاگرام را.

**Baseline:** Zabbix + Elasticsearch + Prometheus + Triage/Application/Infrastructure + Policy + حداکثر 3 Runbook کم‌ریسک + Verification + Audit + Dashboard اولیه.

---

## ADR-014 — Deterministic Cross-Source Incident Correlation

**Status:** ACCEPTED

**Decision:** Correlation بین Zabbix/Elasticsearch/Prometheus/Kubernetes باید deterministic و bounded باشد. Exact `source + source_id` همیشه idempotency کلیدی است؛ merge بین sourceها فقط با stable service/workload identity، signal family محدود، correlation window کوتاه یا correlation key صریح انجام می‌شود.

**Concurrency:** برای جلوگیری از race بین webhookهای همزمان، PostgreSQL transaction advisory lock روی fingerprint استفاده می‌شود.

**Forbidden:** LLM similarity، free-text semantic matching یا hostname حدسی به‌تنهایی حق merge کردن Incidentها را ندارد.

**Safety rule:** در ambiguity، Incidentهای جدا بهتر از over-merge خطرناک هستند.

---

## ADR-015 — MCP Is the Canonical External-Tool Transport

**Status:** ACCEPTED / SUPERSEDES PREVIOUS SELECTED-ONLY POLICY

**Decision:** تمام ارتباط Control Plane با operational toolهای خارجی باید از MCP عبور کند. این شامل Zabbix، Elasticsearch، Prometheus/Alertmanager، Kubernetes، VM/Edge و integrationهای خارجی بعدی است. Control Plane نباید برای Evidence یا Execution مستقیماً credential/API/SSH ابزار مقصد را مصرف کند.

**Boundary:** Agent فقط EvidenceRequest/Recommendation تولید می‌کند. Evidence Collector یا Execution Service قابلیت canonical را انتخاب می‌کند و MCP Client آن را به MCP Server مربوطه می‌فرستد. MCP هرگز Policy/Approval/Tool Registry/Verification/Audit را جایگزین نمی‌کند.

**Trust-zone rule:** MCP Server در trust zone نزدیک ابزار مقصد مستقر می‌شود و خودش با API/SDK/SSH/WinRM محلیِ آن ابزار کار می‌کند. credential ابزار مقصد در Control Plane نگهداری نمی‌شود.

**Production remote MCP requirements:** HTTPS، protocol-version pinning، `Mcp-Method`/`Mcp-Name` route metadata، bearer identity و/یا mTLS، capability allowlist، per-tool authorization، timeout، no token passthrough، Audit و trace correlation. انتخاب نهایی OAuth/EMA/workload-identity provider با PKI سازمان هماهنگ می‌شود.

**Read tools:** Zabbix alert read، Elastic log search، Prometheus metrics، Kubernetes evidence و VM telemetry می‌توانند بدون human approval و طبق read policy استفاده شوند.

**Write tools:** restart/rollback/delete/reboot/change و هر mutation فقط Execution Service → Policy → Approval → MCP Client → MCP Server انجام می‌شود؛ Agent حق MCP write call مستقیم ندارد.

**Native connectors:** native connectorها فقط به‌عنوان MCP server-side adapter، migration/test utility یا isolated development fixture مجازند و canonical Control-Plane path نیستند.

**Forbidden:** arbitrary shell، arbitrary PowerShell، arbitrary Elasticsearch query تولیدشده توسط LLM، dynamic ungoverned tool discovery و direct Control-Plane SSH/Kubernetes access در Production.

---

## ADR-016 — Hybrid Agent Deployment Target

**Status:** ACCEPTED AS TARGET ARCHITECTURE

**Decision:** Reasoning/LLM/Coordinator/RCA/Evaluator/Policy در AIOps Control Plane مرکزی می‌مانند. کنار Linux/Windows/Kubernetes در صورت نیاز Edge Runtime سبک برای telemetry و allowlisted actuation مستقر می‌شود؛ Edge Runtime خودش LLM decision authority ندارد.

**Linux/Windows:** ارتباط Control Plane با Edge Runtime از MCP است. SSH/WinRM فقط پشت Edge/MCP Server و داخل trust zone مقصد قابل استفاده است؛ direct SSH/WinRM از Control Plane مسیر Production نیست.

**Kubernetes:** AI Agent per Pod ممنوع/غیرضروری است. Kubernetes MCP Server می‌تواند کنار control-plane integration service یا Edge DaemonSet مستقر شود؛ reasoning مرکزی باقی می‌ماند.

**Identity target:** Edge/Control-Plane communication باید با bearer/workload identity و ترجیحاً short-lived mTLS محافظت شود؛ provider نهایی با PKI سازمان انتخاب می‌شود.

---

## Open Decisions

### O-001 — Final LLM Model

Status: OPEN

Rule: استفاده از Adapter؛ مدل نهایی بعداً انتخاب می‌شود.

### O-002 — Internal LLM Deployment

Status: OPEN

Rule: اولویت با مدل/سرویس قابل دسترس در شبکه داخلی و Offline Production.

### O-003 — SSO / Identity Provider

Status: OPEN

Rule: MVP با RBAC ساده؛ Production نیازمند SSO/RBAC است.

### O-004 — Message Broker / Distributed Workflow Queue

Status: OPEN

Rule: انتخاب Redis/RabbitMQ/Kafka/Temporal یا گزینه دیگر فقط پس از load/soak evidence و نیاز عملیاتی انجام شود. تا آن زمان هیچ queue technology به Core hard-code نشود.

### O-005 — Advanced Semantic Memory Strategy

Status: OPEN

Rule: PostgreSQL + pgvector baseline است؛ Mem0 یا ابزار دیگر فقط پس از اثبات ارزش استفاده شود.

### O-006 — Workload Identity Provider

Status: OPEN

Rule: SPIFFE/SPIRE الگوی مرجع قوی برای short-lived workload identity/mTLS است، اما انتخاب implementation نهایی باید با PKI و platform سازمان هماهنگ شود.
