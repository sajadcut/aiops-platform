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

## ADR-015 — MCP Is a Selected Capability Transport, Not the Core Execution Authority

**Status:** ACCEPTED

**Decision:** MCP در صورت استفاده، فقط برای integration/edge capabilityهایی به‌کار می‌رود که interoperability آن ارزش واقعی دارد. Native governed connectors برای Observabilityهای ثابت می‌توانند canonical باقی بمانند. MCP هرگز Policy/Approval/Tool Registry را جایگزین نمی‌کند.

**Production remote MCP requirements:** OAuth 2.1، Protected Resource Metadata، resource/audience-bound tokens، HTTPS، token isolation/no passthrough، capability allowlist، per-tool authorization، Audit و در محیط سازمانی workload identity/mTLS.

**Legacy:** `integrations/mcp_client.py` و clientهای وابسته legacy/non-production هستند تا زمانی که adapter استاندارد جدید با این کنترل‌ها ساخته شود.

**Edge MCP:** MCP Server کنار VM/Node فقط به‌عنوان interface یک Edge Runtime constrained قابل قبول است؛ arbitrary shell/PowerShell tool ممنوع است.

---

## ADR-016 — Hybrid Agent Deployment Target

**Status:** ACCEPTED AS TARGET ARCHITECTURE

**Decision:** Reasoning/LLM/Coordinator/RCA/Evaluator/Policy در AIOps Control Plane مرکزی می‌مانند. کنار Linux/Windows/Kubernetes در صورت نیاز Edge Runtime سبک برای telemetry و allowlisted actuation مستقر می‌شود؛ Edge Runtime خودش LLM decision authority ندارد.

**Linux/Windows:** Edge اختیاری است و برای شبکه‌های segmented، credential blast-radius و local diagnostics ترجیح دارد؛ SSH/WinRM می‌تواند برای MVP governed fallback باقی بماند.

**Kubernetes:** AI Agent per Pod ممنوع/غیرضروری است. در صورت نیاز به node-local evidence، Edge Runtime به‌شکل DaemonSet منطقی است؛ reasoning مرکزی باقی می‌ماند.

**Identity target:** Edge/Control-Plane communication باید به سمت short-lived workload identity و mTLS حرکت کند؛ پیاده‌سازی نهایی provider-specific هنوز Open Implementation است.

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
