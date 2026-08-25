# سند مادر پروژه
# AI Ops NeoBankingOperation Platform

**پلتفرم هوشمند عملیات، تشخیص رخداد، تصمیم‌گیری و خودترمیمی کنترل‌شده**

| مشخصه | مقدار |
|---|---|
| نسخه | **2.3 - Benchmark-driven Production Hardening** |
| وضعیت | **Master / Single Source of Truth** |
| هدف | مرجع واحد برای فهم پروژه، طراحی، پیاده‌سازی، تست و ادامه توسعه |
| هسته AI | **Python + LangGraph** |
| لایه سازمانی | **.NET فقط در صورت نیاز برای Integration/API؛ نه هسته AI** |
| محیط هدف | شبکه محدود / **Offline Production** |
| Persistence اصلی | **PostgreSQL** |
| Observability | Elasticsearch + Prometheus + Grafana + Zabbix |
| مالکیت تصمیم‌ها | **Policy + Evidence + Approval + Audit** |

> **قاعده اصلی:** هر AI یا توسعه‌دهنده‌ای که این فایل را دریافت می‌کند باید بتواند بدون تکیه بر حافظه گفت‌وگو، مسئله، معماری، Scope، تصمیم‌های قطعی، وضعیت فعلی و مسیر ادامه کار را بفهمد.

---

# 0. قرارداد استفاده از این سند

این سند فقط مستندات توصیفی نیست؛ **قرارداد پروژه** است. هر تصمیم معماری، تغییر Scope، تغییر فناوری، اضافه‌شدن Agent، تغییر Security Boundary یا تغییر روش Execution باید در همین سند ثبت شود.

- این سند بر فایل‌ها و توضیحات پراکنده اولویت دارد؛ در تعارض، آخرین نسخه این سند مرجع است.
- کد، Configuration و Runbook باید با معماری و قراردادهای این سند سازگار باشند.
- هر توسعه جدید باید مشخص کند مربوط به کدام Phase و کدام Requirement این سند است.
- مواردی که هنوز تصمیم‌گیری نشده‌اند نباید به‌عنوان تصمیم قطعی در کد hard-code شوند.
- هر Phase زمانی کامل است که خروجی، تست، خطاها، امنیت، لاگ، Deploy و معیار پذیرش آن مشخص و قابل ارزیابی باشد.
- هر Batch قابل‌توجه توسعه باید وضعیت سند، موارد تکمیل‌شده، گام بعدی و Open Issueهای مؤثر را به‌روزرسانی کند.

# 1. مسئله و چشم‌انداز

در محیط عملیات بانکی، رخدادها از منابع متعدد تولید می‌شوند: Zabbix، Elasticsearch، Prometheus، Kubernetes، Jenkins/GitLab، VMها، شبکه و سرویس‌های .NET/Java. مشکل اصلی فقط کمبود Alert نیست؛ مشکل، پراکندگی Evidence، زمان تشخیص، وابستگی به تجربه افراد و فاصله بین تشخیص تا اقدام کنترل‌شده است.

هدف این پلتفرم ساخت یک حلقه بسته عملیاتی است:

**دریافت رخداد -> ساخت Context -> تحلیل چندعاملی -> علت ریشه‌ای -> تصمیم مبتنی بر Policy -> اجرای کنترل‌شده -> Verification مستقل -> ذخیره تجربه برای رخدادهای بعدی**

پلتفرم قرار نیست از روز اول اختیار کامل Production را داشته باشد. Automation به‌صورت تدریجی از Observe به Recommend، سپس Approval-based و در نهایت Auto-execute برای Runbookهای کم‌ریسک حرکت می‌کند.

# 2. اصول قطعی پروژه

- Python + LangGraph هسته Orchestration و AI است.
- .NET جزو هسته AI نیست؛ فقط در صورت نیاز، به‌عنوان Integration/API Layer برای اتصال به سرویس‌های موجود یا سازمانی استفاده می‌شود.
- LLM از طریق Adapter/Gateway قابل تعویض است و پروژه به یک Vendor یا Model خاص قفل نمی‌شود.
- Agent بدون Tool/Policy مجاز به تغییر سیستم نیست.
- Execution Layer تنها نقطه مجاز برای تغییر است.
- هر Action باید Audit Trail داشته باشد.
- Production با Non-Production Policy متفاوت دارد.
- در نبود Evidence کافی یا شکست Verification، زنجیره اقدام باید متوقف یا به Human Escalation منتقل شود.
- استقرار باید در شبکه محدود و بدون Internet مستقیم امکان‌پذیر باشد.
- کمینه‌سازی Scope برای MVP از اضافه‌کردن قابلیت‌های نمایشی مهم‌تر است.
- **Evidence زنده Production مرجع حقیقت است؛ RAG و Memory نمی‌توانند جای آن را بگیرند.**
- **Operational Memory با Knowledge RAG یکی نیست و باید در مدل، Retrieval و Policy از هم جدا بمانند.**

# 3. معماری مرجع

**شکل 1 - معماری مرجع پلتفرم AI Ops NeoBankingOperation**

```text
Sources
  |
  v
Data Collection / Normalization
  |
  v
Observability ------------------------------------------------+
  |                                                          |
  v                                                          |
Operational Context -------------------------------------+   |
  |                                                      |   |
  v                                                      |   |
LangGraph AI Brain                                       |   |
  |                                                      |   |
  +--> Specialized Agents ----> RCA ----> Evaluator      |   |
  |                                                      |   |
  +--> Knowledge RAG ------------------------------------+   |
  |                                                          |
  +--> Operational Memory ----------------------------------+
  |
  v
Decision Engine (Policy / Risk / Approval)
  |
  v
Execution Service / Tool Registry
  |
  v
Verification Engine
  |
  +------------------> Audit Service
  |
  +------------------> Operational Memory (Outcome)
```

# 4. لایه‌های معماری

| لایه | مسئولیت | فناوری مرجع | خروجی |
|---|---|---|---|
| 1. منابع | سرویس‌ها و زیرساخت‌های مولد رخداد | Linux/Windows, .NET, Java, Angular, SQL/Oracle, Redis, K8s, VMware, Network | Logs / Metrics / Events / Traces |
| 2. Data Collection | جمع‌آوری و Normalization | Filebeat/Fluent Bit, OTel Collector, Exporters, GitLab/Jenkins Events | Normalized Operational Data |
| 3. Observability | ذخیره و تحلیل Evidence | Elasticsearch, Prometheus, Grafana, Zabbix, Tempo/Jaeger | Searchable Evidence |
| 4. Operational Context | ساخت Context یک Incident | Context Builder + Service Metadata | Incident Context |
| 5. AI Brain | Reasoning, Planning, Routing | Python + LangGraph + LLM Gateway | Hypothesis / Plan |
| 6. Specialized Agents | تحلیل حوزه‌ای | Triage, App, K8s, Infra, Security | Structured Findings |
| 7. Knowledge RAG | بازیابی دانش ایستا/نیمه‌پویا | **PostgreSQL + pgvector + Retriever + LLM Adapter** | Relevant Knowledge |
| 8. Operational Memory | بازیابی تجربه Incidentهای قبلی | **PostgreSQL + pgvector**؛ Memory Framework مانند Mem0 فقط از طریق Adapter | Reusable Patterns |
| 9. Decision & Execution | Policy، Approval و Action | Decision Engine + Execution Tools | Action / Result |
| 10. Verification & Learning | تأیید نتیجه و یادگیری | Verification Engine + Operational Memory | Verified Outcome / Reusable Pattern |

# 5. تفاوت Evidence، RAG و Operational Memory

این سه مفهوم باید از ابتدا از هم تفکیک شوند.

| مفهوم | هدف | نمونه | جایگاه |
|---|---|---|---|
| **Operational Evidence** | فهم وضعیت واقعی فعلی | Log، Metric، Event، Trace، Alert | مرجع اصلی حقیقت برای Incident جاری |
| **Knowledge RAG** | بازیابی دانش و مستندات | Runbook، معماری، SOP، Troubleshooting Guide | کمک به Reasoning و انتخاب Plan |
| **Operational Memory** | استفاده از تجربه Incidentهای قبلی | Cause، Action، Verification، Outcome | کمک به Hypothesis و Reuse |

## 5.1 اصل معماری

- Evidence زنده باید مستقیماً از Observability و Sourceهای عملیاتی Query شود.
- Knowledge RAG برای مستندات، Runbookها، معماری و دانش سازمانی استفاده می‌شود.
- Operational Memory برای تجربه عملیاتی ثبت‌شده استفاده می‌شود.
- Memory یا RAG نباید به‌تنهایی مبنای Write Action در Production قرار گیرد.
- اگر Memory با Evidence فعلی تعارض داشته باشد، **Evidence فعلی اولویت دارد**.
- برای MVP، **PostgreSQL + pgvector** لایه پایه Vector Search برای Knowledge RAG و Operational Memory است. Mem0 اختیاری است و فقط از طریق Adapter قابل استفاده خواهد بود.

## 5.2 قرارداد Storage و Vector Layer

- **PostgreSQL** تنها Persistence اصلی پروژه است و داده‌های Relational، Audit، Incident، Runbook، Knowledge و Memory را نگهداری می‌کند.
- **pgvector** به‌عنوان extension PostgreSQL، Vector Search مشترک Knowledge RAG و Operational Memory را فراهم می‌کند.
- Embeddingها در PostgreSQL نگهداری می‌شوند و Metadata/ACL/Source Reference کنار آن‌ها باقی می‌ماند تا Retrieval قابل Audit باشد.
- RAG و Memory باید Namespace/Collection منطقی جدا داشته باشند و Policy دسترسی مستقل داشته باشند، حتی اگر Storage فیزیکی مشترک باشد.
- **Mem0 در معماری Core اجباری نیست**؛ در صورت انتخاب، از طریق `mem0_adapter` به Operational Memory متصل می‌شود و Domain Contract داخلی پروژه نباید به API اختصاصی Mem0 وابسته شود.
- Qdrant، Milvus و سایر Vector DBهای مستقل در MVP خارج از Scope هستند؛ فقط با ADR جدید و در صورت اثبات نیاز Scale/Performance اضافه می‌شوند.

# 6. هسته نرم‌افزار و Stack قطعی

| جزء | انتخاب | وضعیت تصمیم |
|---|---|---|
| AI Orchestration | Python + LangGraph | قطعی |
| AI Agents | Python | قطعی |
| LLM Integration | Adapter / Gateway | قطعی؛ Model نهایی باز |
| Primary Operational DB / Persistence | **PostgreSQL** | **قطعی** |
| Observability | Elasticsearch + Prometheus + Grafana + Zabbix | قطعی بر مبنای زیرساخت موجود |
| Tracing | Tempo / Jaeger | در صورت وجود/نیاز |
| Cache/Lock | Redis | اختیاری/نیازمحور |
| Execution | Ansible / SSH / PowerShell / Jenkins API / K8s API / VMware API | قطعی در سطح قابلیت؛ Tool در هر Runbook مشخص می‌شود |
| .NET | Integration/API در صورت نیاز | اختیاری؛ هسته AI نیست |
| Container | Docker | قطعی |
| Target Orchestration | Kubernetes/OpenShift | بعد از MVP یا در صورت نیاز محیط |
| Knowledge RAG | **PostgreSQL + pgvector + Retriever** | **قطعی برای MVP** |
| Operational Memory | **PostgreSQL + pgvector** | **قطعی برای MVP؛ Memory Framework مانند Mem0 اختیاری** |

# 7. چرا Python + LangGraph؟

پروژه ماهیت Agentic و Workflow محور دارد و بیشترین پیچیدگی در State، Routing، Parallelization، Tool Calling، Evaluation و کنترل چرخه تصمیم است. بنابراین Python + LangGraph به‌عنوان هسته طبیعی این پروژه انتخاب می‌شود. وجود سرویس‌های .NET در سازمان به معنی الزام پیاده‌سازی هسته AI با .NET نیست.

اصل مرزی:

> **سیستم‌های موجود می‌توانند .NET باشند؛ مغز و Orchestrator پلتفرم Python است.**

# 8. اجزای نرم‌افزاری

| Component | وظیفه | نکته اجرایی |
|---|---|---|
| Alert Gateway | دریافت، Normalize، Dedup، Correlate Alertها | ابتدا Zabbix؛ بعداً Alertmanager و منابع دیگر |
| Incident Service | چرخه عمر Incident | Create / Update / Close / Escalate |
| Context Builder | جمع‌کردن Evidence مرتبط | باید قبل از Reasoning اجرا شود |
| LangGraph Orchestrator | Routing و هماهنگی Node/Agentها | State ماشین مرکزی Workflow |
| Agent Layer | تحلیل دامنه‌ای | خروجی Structured و قابل ارزیابی |
| Knowledge RAG Service | بازیابی مستندات و دانش | فقط Context کمکی؛ نه جایگزین Evidence |
| Operational Memory Service | بازیابی Incident Patternها | در MVP روی PostgreSQL |
| RCA Engine | تولید و رتبه‌بندی Hypothesis | Evidence-linked |
| Evaluator | بررسی کیفیت تشخیص/Plan | از اجرای Plan ضعیف جلوگیری می‌کند |
| Decision Engine | Policy، Risk، Approval | بدون LLM به‌عنوان اختیار نهایی |
| Execution Service | اجرای Tool/Runbook | Only write-capable boundary |
| Verification Service | بررسی مستقل Success/Failure | نباید فقط به گزارش Agent اعتماد کند |
| Audit Service | ثبت تصمیم و Action | در مسیر عادی عملیات غیرقابل حذف |

# 9. Agentهای پایه

| Agent | ورودی اصلی | خروجی استاندارد | محدودیت |
|---|---|---|---|
| Alert Triage | Alert + Service metadata | severity, category, scope, confidence | هیچ تغییر عملیاتی |
| Application Agent | Logs + Deployment + Metrics | findings, suspicious_release, evidence_ids | هیچ تغییر عملیاتی |
| Kubernetes Agent | K8s events, pod status, probes, resources | k8s_health, likely_cause, evidence_ids | هیچ تغییر عملیاتی |
| Infrastructure Agent | CPU/RAM/Disk/Network/VM metrics | infra_findings, anomaly | هیچ تغییر عملیاتی |
| Security Agent | Security logs/events | risk, indicators, recommendation | در MVP فقط تحلیل |
| Execution Agent | Approved ActionPlan | execution_result | فقط Runbook مجاز |
| Verification Agent/Service | Before/After checks | verified_status, evidence, confidence | مرجع مستقل موفقیت |

# 10. قرارداد داده و State

State مرکزی LangGraph باید بتواند کل Incident را بدون اتکا به متن آزاد مدیریت کند. طراحی دقیق فیلدها در Phase 0 تثبیت می‌شود.

| Object | حداقل اطلاعات |
|---|---|
| Incident | id, source, severity, service, started_at, status, summary |
| Context | service, dependencies, recent deployments, time window, evidence_refs |
| Evidence | id, type, source, query, time_range, reference, confidence |
| Finding | agent, finding_type, statement, evidence_ids, confidence |
| Hypothesis | cause, supporting_evidence, conflicting_evidence, confidence |
| ActionPlan | action_id, runbook, risk, prerequisites, rollback, expected_effect |
| Approval | required, approver, decision, reason, timestamp |
| Execution | tool, target, started_at, finished_at, status, result_ref |
| Verification | checks, before, after, status, confidence |
| MemoryEntry | pattern, conditions, solution, evidence, outcome, reuse_count, embedding_ref, namespace |
| KnowledgeDocument | id, source, title, version, metadata, chunk_refs, embedding_model, embedding_status, status |

# 11. جریان کامل Incident

1. Zabbix/Alert Source رخداد را می‌فرستد.
2. Alert Gateway رخداد را Normalize و Deduplicate می‌کند و Incident ID می‌سازد.
3. Context Builder Service/Environment/Deployment را تشخیص داده و Evidence لازم را می‌گیرد.
4. Knowledge RAG در صورت نیاز دانش مرتبط مانند Runbook یا مستندات را بازیابی می‌کند.
5. Operational Memory در صورت وجود Similar Incident، Pattern یا Outcome قبلی را بازیابی می‌کند.
6. LangGraph Orchestrator مشخص می‌کند کدام Agentها Sequential یا Parallel اجرا شوند.
7. Agentها Findings ساختاریافته تولید می‌کنند.
8. RCA Engine Hypothesisها را با Evidence پیوند می‌دهد.
9. Evaluator بررسی می‌کند Evidence برای تصمیم کافی هست یا نه.
10. Decision Engine براساس Risk/Policy تعیین می‌کند Suggest، Approval یا Auto-execute.
11. Execution Service فقط ActionPlan مجاز را اجرا می‌کند.
12. Verification مستقل Health/Metric/Log/State را قبل و بعد مقایسه می‌کند.
13. نتیجه در Audit و Operational Memory ذخیره می‌شود.
14. Incident بسته، Escalate یا وارد Human Review می‌شود.

# 12. سطح خودکارسازی

| Level | رفتار | هدف |
|---|---|---|
| L0 - Observe | فقط مشاهده و تحلیل؛ هیچ Action | تأسیس داده و اعتماد |
| L1 - Recommend | AI پیشنهاد می‌دهد، انسان اجرا می‌کند | اعتبارسنجی تشخیص |
| L2 - Approval | AI Plan می‌سازد؛ Human Approve؛ سیستم اجرا می‌کند | اتوماسیون کنترل‌شده |
| L3 - Guarded Auto | فقط Runbook کم‌ریسک و Policy-approved خودکار | کاهش MTTR |
| L4 - Adaptive Auto | اتوماسیون گسترده با Guardrail و Rollback | هدف بلندمدت؛ خارج از MVP |

# 13. Security و Governance

- Credential خام هرگز وارد Prompt، Memory، Log یا Audit نمی‌شود.
- Tool Registry باید Allowlist، Timeout، Scope، محیط و Risk Level داشته باشد.
- Production Write Action پیش‌فرض Deny است مگر Policy صراحتاً اجازه دهد.
- High-Risk Actions نیازمند Approval هستند.
- Runbook باید Owner، Version، Preconditions، Steps، Timeout و Rollback داشته باشد.
- Execution باید Idempotent تا حد امکان باشد.
- Audit باید شامل Incident، Plan، Policy decision، Approval، Tool call، Result و Verification باشد.
- ارتباط داخلی سرویس‌ها باید Authentication و حداقل دسترسی داشته باشد.
- در Offline Production، Artifact و Model باید از Registry/Repository داخلی تأمین شوند.
- RAG Retriever فقط باید به منابع و اسناد Allowlist شده دسترسی داشته باشد.
- خروجی RAG و Memory باید Metadata و Source Reference داشته باشد تا قابل Audit باشند.

# 14. MVP دقیق

MVP نباید کل دیاگرام را پیاده کند. هدف MVP اثبات یک حلقه کامل و قابل اعتماد است.

| MVP Area | انتخاب |
|---|---|
| Alert Source | Zabbix |
| Evidence | Elasticsearch + Prometheus |
| Orchestrator | Python + LangGraph |
| Agents | Alert Triage + Application + Infrastructure |
| Decision | Policy-based ساده |
| Execution | یک Tool مسیر مشخص؛ ترجیحاً Ansible یا Jenkins API |
| Runbooks | حداکثر 3 Runbook کم‌ریسک |
| Verification | چند Health/Metric/Log Check ثابت |
| Persistence | **PostgreSQL** |
| Knowledge RAG | **Runbook/Knowledge محدود و کنترل‌شده؛ PostgreSQL + pgvector** |
| Operational Memory | **PostgreSQL + pgvector؛ Semantic Similarity در MVP** |
| UI | Dashboard اولیه Incident / Status / Automation Success |
| Security | RBAC پایه + Audit + Approval |

# 15. سناریوهای مرجع MVP

| سناریو | مسیر |
|---|---|
| Application Error Spike | HTTP 5xx -> Logs -> بررسی Release -> Hypothesis -> Approval -> Rollback -> Verify error rate |
| Kubernetes CrashLoop | Alert -> Pod/Events/Probe/Logs -> تشخیص Config/Dependency/Resource -> Runbook -> Verify Ready/Traffic |
| Infrastructure Pressure | CPU/RAM/Disk -> Trend + Service Correlation -> Action کم‌ریسک -> Execute -> Verify |

# 16. فازهای پیاده‌سازی

ترتیب فازها بر اساس کاهش ریسک و ساخت یک مسیر قابل تست است؛ هر فاز باید قابل اجرا و قابل تحویل باشد. عبور به Phase بعد فقط با Exit Criteria انجام می‌شود.

## Phase 0 - Foundation & Contracts

هدف: ساخت اسکلت پایدار و قراردادهای پروژه بدون ورود عمیق به AI.

**خروجی‌ها:** Repository؛ Python project؛ LangGraph skeleton؛ Config management؛ structured logging؛ PostgreSQL schema اولیه؛ LLM Adapter؛ Tool Registry؛ Agent/State contracts؛ Docker؛ CI/CD داخلی.

**Guardrail:** در این فاز هیچ Production Action خودکار نمی‌شود.

**Exit Criteria:** Repository build می‌شود؛ test پایه؛ service health؛ schema migration؛ mock LLM و mock tool قابل اجرا.

## Phase 1 - Observability Connectors & Context

هدف: تبدیل داده پراکنده به Incident Context قابل استفاده.

**خروجی‌ها:** Zabbix connector؛ Elasticsearch query layer؛ Prometheus query layer؛ Alert Gateway؛ Incident service؛ Context Builder؛ correlation اولیه.

**Guardrail:** هنوز تصمیم‌گیری AI و Execution واقعی محدود است.

**Exit Criteria:** یک Alert واقعی به Incident + Context با Evidence قابل مشاهده تبدیل شود.

## Phase 2 - LangGraph Intelligence

هدف: ساخت مغز تحلیل و Agentها.

**خروجی‌ها:** LangGraph StateGraph؛ Triage Agent؛ Application Agent؛ Infrastructure Agent؛ parallel fan-out؛ RCA؛ Evaluator؛ structured outputs؛ confidence.

**Guardrail:** Agentها فقط تحلیل/پیشنهاد می‌دهند.

**Exit Criteria:** برای سناریوهای مرجع، diagnosis و evidence_ids قابل ارزیابی تولید شود.

## Phase 3 - Knowledge RAG & Operational Memory

هدف: افزودن دانش و تجربه قابل بازیابی با **PostgreSQL + pgvector** به‌عنوان Vector Layer مشترک.

**خروجی‌ها:** Knowledge Document model؛ document ingestion؛ chunking؛ embedding generation؛ pgvector extension/schema؛ metadata/filter retrieval؛ Runbook/Architecture retrieval؛ Operational Memory model؛ ثبت Outcome؛ semantic similarity/reuse اولیه.

**Guardrail:** RAG و Memory فقط Context کمکی هستند؛ Evidence زنده Production مرجع حقیقت باقی می‌ماند.

**Exit Criteria:** یک Incident بتواند دانش مرتبط و Incident Pattern قبلی را بازیابی کند و Source/Metadata هر مورد مشخص باشد.

## Phase 4 - Decision & Controlled Automation

هدف: تبدیل Recommendation به Action کنترل‌شده.

**خروجی‌ها:** Policy engine؛ Risk classification؛ Approval flow؛ Runbook Registry؛ Execution Service؛ Ansible/Jenkins/K8s tool adapters؛ rollback.

**Guardrail:** Auto-execute فقط برای Runbookهای مشخص و کم‌ریسک.

**Exit Criteria:** یک Action با Audit کامل و Approval اجرا و قابل rollback باشد.

## Phase 5 - Verification & Operational Learning

هدف: بسته‌شدن حلقه و یادگیری از نتیجه.

**خروجی‌ها:** Verification Engine؛ before/after؛ outcome classifier؛ Memory reuse؛ learning feedback؛ incident similarity بهبود‌یافته.

**Guardrail:** Memory منبع حقیقت برای Evidence نیست؛ تجربه کمکی است.

**Exit Criteria:** بعد از Execute، Verify مستقل انجام شود و نتیجه در Memory ذخیره/بازیابی شود.

## Phase 6 - Production Hardening

هدف: آماده‌سازی برای محیط واقعی.

**خروجی‌ها:** RBAC/SSO؛ HA؛ retries؛ timeout؛ rate limiting؛ observability خود پلتفرم؛ audit retention؛ backup/restore؛ secret integration؛ offline deployment.

**Guardrail:** هیچ قابلیت هوشمند جدیدی لازم نیست؛ تمرکز روی قابلیت اتکا.

**Exit Criteria:** نصب تکرارپذیر، recovery و security review قابل انجام باشد.

## Phase 7 - Scale & Advanced Agents

هدف: افزایش پوشش و بلوغ.

**خروجی‌ها:** K8s Agent پیشرفته؛ Security Agent؛ Jenkins/GitLab intelligence؛ VMware؛ richer memory؛ semantic retrieval در صورت اثبات نیاز؛ adaptive policies؛ more runbooks.

**Guardrail:** این فاز فقط بعد از اثبات MVP و Production Hardening.

**Exit Criteria:** افزایش Automation Success و کاهش MTTR بدون افزایش Risk.

# 17. ترتیب پیشنهادی اجرای کد

1. ساخت monorepo و قرارداد packageها.
2. ساخت config/env و logging مشترک.
3. ساخت PostgreSQL models و migration.
4. ساخت LLM Adapter با Mock Provider.
5. ساخت LangGraph state و graph پایه بدون Agent واقعی.
6. ساخت Alert Gateway + Zabbix adapter.
7. ساخت Elasticsearch/Prometheus evidence clients.
8. ساخت Context Builder.
9. پیاده‌سازی Triage Agent.
10. پیاده‌سازی Application و Infrastructure Agent و parallelization.
11. پیاده‌سازی RCA + Evaluator.
12. ساخت Knowledge RAG پایه برای Runbook/Architecture.
13. ساخت Operational Memory و persistence.
14. ساخت Decision Engine و Policy model.
15. ساخت یک Runbook واقعی و Execution Adapter.
16. ساخت Verification برای همان سناریو.
17. ثبت Audit و Memory و Dashboard.
18. سپس توسعه Runbookها و Agentهای بیشتر.

# 18. ساختار Repository مرجع

```text
aiops-platform/
├── apps/
│   ├── api/                         # FastAPI / API layer
│   ├── orchestrator/                # LangGraph
│   ├── alert_gateway/
│   ├── context_service/
│   ├── rag_service/
│   ├── memory_service/
│   ├── execution_service/
│   └── verification_service/
├── agents/
│   ├── triage/
│   ├── application/
│   ├── infrastructure/
│   ├── kubernetes/
│   └── security/
├── domain/                           # models, policies, contracts
├── integrations/
│   ├── zabbix/
│   ├── elasticsearch/
│   ├── prometheus/
│   ├── jenkins/
│   ├── kubernetes/
│   ├── vmware/
│   └── ssh/
├── knowledge/
│   ├── documents/
│   ├── loaders/
│   └── retrieval/
├── memory/
│   ├── models/
│   ├── retrieval/
│   ├── ranking/
│   ├── pgvector/
│   └── adapters/
│       └── mem0_adapter.py
├── runbooks/
├── database/
│   ├── migrations/
│   └── extensions/
│       └── pgvector/
├── deployment/
│   ├── docker/
│   └── kubernetes/
├── dashboards/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── scenarios/
└── docs/
    ├── master/
    ├── adr/
    └── runbooks/
```

اگر در محیط سازمانی یک سرویس .NET لازم باشد، آن سرویس باید زیر `integrations` یا `enterprise-adapters` قرار بگیرد و نباید LangGraph را به .NET منتقل کند مگر اینکه یک ADR جدید این تصمیم را صریحاً تغییر دهد.

# 19. APIهای منطقی

| Method | Endpoint | کاربرد |
|---|---|---|
| POST | /api/v1/incidents | ساخت/دریافت Incident |
| GET | /api/v1/incidents/{id} | وضعیت Incident |
| POST | /api/v1/incidents/{id}/analyze | شروع تحلیل |
| GET | /api/v1/incidents/{id}/context | Context |
| GET | /api/v1/incidents/{id}/evidence | Evidence |
| GET | /api/v1/incidents/{id}/knowledge | Knowledge RAG results |
| GET | /api/v1/incidents/{id}/memory | Relevant operational memory |
| GET | /api/v1/incidents/{id}/plan | ActionPlan |
| POST | /api/v1/incidents/{id}/approve | Approval |
| POST | /api/v1/incidents/{id}/execute | اجرای Action |
| GET | /api/v1/incidents/{id}/verification | Verification |
| GET/POST | /api/v1/runbooks | مدیریت Runbook |
| GET/POST | /api/v1/knowledge | مدیریت Knowledge documents |
| GET | /api/v1/health | Health Check |

# 20. KPI و معیار موفقیت

| KPI | تعریف |
|---|---|
| MTTD | زمان از وقوع تا شناسایی/ایجاد Incident |
| MTTR | زمان از شناسایی تا Recovery |
| Diagnosis Accuracy | درصد تشخیص‌های قابل تأیید |
| Evidence Coverage | درصد claims دارای Evidence معتبر |
| Automation Success Rate | درصد Actionهای موفق پس از Verification |
| False Diagnosis Rate | درصد تشخیص‌های نادرست |
| Rollback Rate | نسبت Actionهایی که rollback شده‌اند |
| Human Approval Rate | درصد Actionهای نیازمند Approval |
| Verification Confidence | اعتماد به نتیجه Verify |
| Reuse Rate | درصد Incidentهایی که از Memory الگوی مفید گرفته‌اند |
| RAG Relevance | درصد Retrievalهای دانش که توسط ارزیابی انسانی/سناریویی مرتبط تشخیص داده شده‌اند |

# 21. تست و کیفیت

- Unit Test برای Policy، State Transition، Agent Parser و Tool Contracts.
- Integration Test برای Zabbix/ELK/Prometheus با Mock و محیط واقعی کنترل‌شده.
- Scenario Test برای سه Incident مرجع.
- Failure Injection برای Timeout، API Failure، Missing Evidence و Verification Failure.
- Security Test برای Privilege Escalation، Secret Leakage و Tool Allowlist.
- Regression Set برای Prompt/Agent behavior؛ خروجی‌های ساختاریافته باید پایدار بمانند.
- هر Runbook قبل از Production باید Dry-run و Rollback Test داشته باشد.
- Knowledge RAG باید با مجموعه تست ثابت برای Retrieval Relevance ارزیابی شود.
- Memory Reuse باید با Scenarioهای واقعی یا بازسازی‌شده بررسی شود و False Reuse پایش شود.

# 22. تصمیم‌های باز (Open Decisions)

| موضوع | وضعیت | قاعده تا زمان تصمیم |
|---|---|---|
| مدل LLM نهایی | باز | از Adapter استفاده شود؛ هیچ Agent نباید مستقیم به یک SDK مدل وابسته باشد. |
| محل LLM | باز | اولویت با مدل/سرویس قابل دسترس در شبکه داخلی. |
| Auth/SSO Provider | باز | OIDC/RBAC در کد وجود دارد؛ provider/role mapping نهایی با محیط سازمانی validate شود. |
| **Vector Store / pgvector** | **قطعی** | **PostgreSQL + pgvector لایه Vector مشترک RAG و Memory در MVP است.** |
| **Memory framework مانند Mem0** | **اختیاری** | **فقط از طریق Adapter؛ Mem0 نباید dependency اجباری یا API داخلی اصلی پروژه باشد.** |
| Message Broker / Distributed Worker Queue | باز | در MVP hard-code نشود؛ انتخاب Redis/RabbitMQ/Kafka/Temporal یا گزینه دیگر فقط پس از load/soak evidence و ADR. |
| MCP | **Selected / Governed only** | MCP transport عمومی Core نیست؛ legacy client non-production است؛ remote MCP نیازمند OAuth 2.1/resource binding/capability policy/Audit و workload identity مناسب است. |
| Workload Identity Provider | باز | short-lived workload identity/mTLS لازم است؛ SPIFFE/SPIRE الگوی مرجع است ولی انتخاب نهایی با PKI سازمان. |
| Framework API | پیشنهادی | FastAPI انتخاب پیشنهادی برای Python API؛ الزام مطلق نیست. |
| Deployment | باز | Docker در توسعه؛ Kubernetes/OpenShift برای محیط پایدار. |
| سطح Auto-execute | Policy-driven | فقط Runbookهای کم‌ریسک و مشخص. |
| Multi-tenancy | باز | در MVP خارج از Scope. |

# 23. ADRهای الزامی و تصمیم‌های تکمیلی

ADRهای رسمی و شماره‌گذاری جاری در `docs/adr/DECISIONS.md` نگهداری می‌شوند. حداقل تصمیم‌های زیر باید معتبر بمانند:

- Python + LangGraph به‌عنوان AI Core.
- PostgreSQL + pgvector به‌عنوان Persistence/Vector baseline.
- Evidence First و جدایی RAG/Memory از Live Evidence.
- Execution Boundary و منع write مستقیم توسط Agent/LLM.
- Approval/Risk/Verification مستقل.
- Deterministic cross-source Incident correlation؛ LLM مجاز به merge authority نیست.
- MCP فقط selected capability transport و نه جایگزین Tool Registry/Policy/Approval.
- Hybrid deployment target: reasoning مرکزی + Edge Runtime اختیاری و constrained؛ بدون per-host/per-Pod LLM authority.

# 24. وضعیت فعلی پروژه — 2026-08-26

پیاده‌سازی repository از وضعیت تاریخی Phase 0 عبور کرده است. پروژه اکنون یک **advanced governed AIOps implementation** است، اما هنوز strict Production Accepted نیست. وضعیت عملی فعلی عمدتاً **Phase 6 - Production Hardening** با gapهای باقی‌مانده در Phase 4/5/7 است.

| مورد | وضعیت فعلی |
|---|---|
| Architecture | Implemented / evolving under ADR control |
| Signal Gateway | Implemented; source-agnostic |
| Exact event idempotency | Implemented + PostgreSQL transaction lock |
| Cross-source correlation | Implemented for conservative deterministic families + bounded window; real corpus acceptance pending |
| Asset Identity | Implemented deterministic multi-source resolver; CMDB authority pending |
| Zabbix / Elasticsearch / Prometheus | Governed connectors implemented; real customer endpoint acceptance pending |
| Kubernetes Evidence | Read-only integration implemented; write/remediation breadth partial |
| VM | Linux governed telemetry/remediation implemented; Windows native constrained path pending |
| LangGraph workflow | Implemented with durable application checkpoint/resume |
| Agent Layer | Triage + 13 specialist agents implemented; analysis-only |
| Multi-agent collaboration | Structured peer context, handoff, coordination and bounded evidence refresh implemented |
| RCA / Evaluator | Implemented; Evaluator mandatory before Decision |
| Decision / Policy / Approval | Implemented with concrete tool/action/target risk binding |
| Execution | Governed Tool Registry; Linux strongest; adapter breadth partial |
| Verification | Fresh before/after + metric semantics implemented; per-action SLO objectives partial |
| Knowledge RAG | Implemented on PostgreSQL + pgvector with governance/ACL metadata |
| Operational Memory | Implemented separately from RAG; verified-outcome reuse contract |
| Persistence / Audit | PostgreSQL models/migrations/checkpoints/approval/audit implemented |
| OIDC / RBAC | Repository implementation exists; enterprise issuer/role acceptance pending |
| MCP | Legacy transport explicitly non-production; modern selected adapter not yet implemented |
| Offline Docker/Kubernetes | Hardened repository definitions exist; real internal artifact promotion pending |
| CI | Unit/integration/scenario/security + PostgreSQL/pgvector migration acceptance configured |
| HA / DR / Scale | Partial; PostgreSQL HA, distributed queue/rate limit, backup/PITR/DR, load/chaos acceptance pending |
| Production readiness | **Not yet strict Production Ready** |

**Current practical Phase: Phase 6 - Production Hardening**

### 24.1 Completed Items

- Canonical Evidence-first multi-source incident flow.
- Deterministic asset/service context and source failure vs zero-result semantics.
- Source-agnostic trigger path including ELK-first and Prometheus-first incidents.
- Exact source-event deduplication and deterministic bounded cross-source correlation with PostgreSQL advisory locks.
- Triage + specialist multi-agent collaboration, RCA and Evaluator gate.
- Policy/Approval/Execution separation with write authority outside LLM Agents.
- Governed Linux VM remediation, fresh Verification baseline and verified Memory learning.
- PostgreSQL + pgvector persistence for Incident/RAG/Memory/governance.
- OIDC/RBAC repository contract, Audit, CI, offline container and Kubernetes hardening.
- 2026 benchmark review against NIST/OWASP/MCP/OTel/OPA/SPIFFE/Sigstore and mature operations automation patterns; matrix in `docs/BENCHMARK_2026.md`.

### 24.2 Next Steps

1. Real Zabbix/Elasticsearch/Prometheus acceptance + CMDB/service catalog mapping.
2. Correlation corpus benchmark with false-merge/false-split targets and late-signal re-analysis semantics.
3. Windows constrained Edge/WinRM/JEA telemetry and remediation; no arbitrary PowerShell.
4. Per-runbook verification objectives/SLOs.
5. Broader governed K8s/Ansible/Jenkins/DB/network execution adapters and rollback drills.
6. Decide and implement distributed queue/workers/backpressure after load evidence.
7. Distributed rate limiting and 500-concurrent-Incident load/soak acceptance.
8. PostgreSQL HA + backup/restore/PITR/DR exercise.
9. Enterprise OIDC + short-lived workload identity/mTLS.
10. OpenTelemetry GenAI/Agent/Tool traces and metrics with sensitive-content controls.
11. Implement modern governed MCP adapter only for selected integrations if justified.
12. Immutable signed offline promotion + branch/ruleset protection + formal red-team/chaos acceptance.

### 24.3 Open Issues / Production Blockers

- Real observability, LLM and remediation endpoints have not been externally accepted in the target restricted network.
- CMDB/service catalog is not yet authoritative identity source.
- Windows native execution/telemetry is incomplete.
- Message broker/distributed worker architecture is undecided and 500-Incident concurrency is not proven.
- API rate limiting is not distributed across replicas.
- PostgreSQL HA/backup/PITR/DR is not accepted.
- Workload identity/mTLS rotation is not implemented end-to-end.
- Agent/LLM telemetry is not yet full OpenTelemetry GenAI instrumentation.
- Legacy MCP clients are not production-capable under current MCP authorization requirements.
- Action-specific verification SLOs are incomplete.
- Load/soak/chaos and formal agentic red-team evidence remain incomplete.
- Production artifact/model signing and internal registry promotion require external validation.

# 25. قرارداد ادامه کار با AI / Developer

1. ابتدا نسخه سند و Current Status را بخوان؛ فرض نکن چیزی که در طرح آمده حتماً پیاده شده است.
2. ابتدا Phase فعلی را تشخیص بده و فقط از همان Phase کار را ادامه بده.
3. قبل از تغییر معماری، Decisionهای قطعی را بررسی کن؛ تغییر معماری بدون ADR/به‌روزرسانی سند مجاز نیست.
4. هر کدی که می‌نویسی باید به Component، Phase و Requirement مشخصی از این سند متصل باشد.
5. اگر یک Capability هنوز Open Decision است، آن را به‌صورت configurable یا adapter-based پیاده کن.
6. در پاسخ‌ها و طراحی‌ها، Production Safety، Audit و Verification را کنار نگذار.
7. پس از هر Batch قابل‌توجه، Current Status، Completed Items، Next Steps و Open Issues را در سند یا Change Log به‌روزرسانی کن.
8. هیچ قابلیت بزرگ جدیدی فقط به دلیل جذاب‌بودن اضافه نکن؛ ابتدا بررسی کن آیا برای MVP ضروری است.
9. اگر بین سادگی MVP و پیچیدگی معماری تعارض بود، انتخاب پیش‌فرض MVP است مگر Risk یا Requirement خلاف آن باشد.
10. **Evidence جاری را از Memory/RAG مستقل نگه دار و هرگز Retrieval را جایگزین مشاهده مستقیم سیستم نکن.**

# 26. Change Log

| نسخه | تغییر | دلیل |
|---|---|---|
| 2.0 | اصلاح Backend Core از .NET به Python + LangGraph؛ بازطراحی Repository و فازها؛ افزودن Current Status و AI Continuation Contract | رفع تناقض معماری و تبدیل سند به مرجع قابل استفاده در ادامه پروژه |
| **2.1** | **اصلاح Persistence از SQL Server به PostgreSQL؛ اضافه‌شدن مرزبندی رسمی Evidence / Knowledge RAG / Operational Memory؛ افزودن RAG و Memory به معماری، فازها، API و Repository** | **شفاف‌سازی معماری دانش و حافظه** |
| **2.2** | **تثبیت PostgreSQL + pgvector به‌عنوان Persistence و Vector Layer مشترک برای RAG و Operational Memory؛ تعریف Mem0 به‌عنوان Adapter اختیاری؛ انتقال Semantic Retrieval به MVP** | **هم‌راستا کردن معماری با الگوی عملیاتی مناسب برای RAG/Memory و حذف ابهام بین Storage، Vector Search و Memory Framework** |
| **2.3** | **Sync وضعیت واقعی implementation؛ deterministic cross-source correlation؛ MCP governance؛ hybrid central/edge target؛ benchmark 2026؛ production gaps و Next Steps واقعی** | **حذف drift بین SSoT و repository و هم‌راستایی با الگوهای امن Agentic/AIOps 2026 بدون ادعای Production Ready زودهنگام** |

# 27. Definition of Done پروژه

پروژه زمانی از نظر هر Feature یا Phase Done است که کد، تست، Error Handling، Logging، Security، Audit، Deployment، Rollback (در صورت مرتبط بودن)، Documentation و Scenario Acceptance آن موجود و قابل اجرا باشد. «کد نوشته شد» به‌تنهایی Done محسوب نمی‌شود.

# 28. خروجی مورد انتظار نهایی

در وضعیت نهایی، یک Incident واقعی باید بتواند از Alert تا Verified Resolution بدون گسست طی شود:

**Alert -> Context -> Evidence + Knowledge RAG + Operational Memory -> Agents -> RCA -> Evaluation -> Decision -> Approval/Policy -> Execution -> Verification -> Memory**

هر مرحله باید قابل مشاهده، Audit و قابل تست باشد.

---

## ضمیمه A - قرارداد عملیاتی RAG

### A.1 منابع مجاز

RAG در حالت پیش‌فرض فقط از منابعی استفاده می‌کند که به‌عنوان Knowledge Source ثبت و Allowlist شده‌اند؛ نمونه‌ها:

- Runbookها
- SOPها
- مستندات معماری
- Dependency/Service Catalog
- استانداردهای داخلی عملیات
- Troubleshooting Guide

### A.2 منابع غیرمجاز به‌عنوان حقیقت Incident

- خروجی Memory به‌تنهایی
- پاسخ آزاد یک Agent بدون Evidence
- متن قدیمی بدون Version/Validity
- هر منبعی که مالک، Version یا منبع آن مشخص نیست

### A.3 قرارداد Retrieval

هر نتیجه RAG باید حداقل شامل `source_id`، `title`، `version`، `relevance` و `retrieved_at` باشد.

### A.4 Rule

**RAG می‌تواند بگوید «طبق Runbook چه کاری معمولاً انجام می‌شود»، اما Evidence باید نشان دهد «الان واقعاً چه اتفاقی افتاده است».**

## ضمیمه B - قرارداد Operational Memory

هر Memory Entry حداقل باید شامل موارد زیر باشد:

- Incident Pattern
- Conditions / Symptoms
- Root Cause
- Evidence References
- Action
- Verification Result
- Outcome
- Environment / Service Scope
- Timestamp
- Source Incident ID
- Reuse Count

Memory Entry بدون Outcome معتبر نباید به‌عنوان Pattern موفق پیشنهاد شود.

## ضمیمه C - اصل معماری نهایی

> **Observe with Evidence. Reason with LangGraph. Consult Knowledge with RAG. Reuse experience with Operational Memory. Decide with Policy. Change only through Execution Boundary. Trust success only after independent Verification.**

## ضمیمه D - قرارداد pgvector و Mem0

### D.1 pgvector

`pgvector` بخشی از Persistence Architecture است، نه یک سرویس AI مستقل. Embeddingهای Knowledge و Memory در PostgreSQL ذخیره می‌شوند و Retrieval با Semantic Similarity و فیلترهای Metadata انجام می‌شود.

### D.2 Mem0

Mem0 در صورت استفاده، فقط یک Memory Management Layer/Adapter است. انتخاب یا حذف آن نباید Schema، Domain Contract یا LangGraph State را بشکند.

### D.3 Rule

**PostgreSQL = System of Record؛ pgvector = Semantic Retrieval؛ RAG = Knowledge Retrieval؛ Operational Memory = تجربه عملیاتی؛ Mem0 = گزینه Framework برای مدیریت Memory، نه منبع حقیقت و نه وابستگی اجباری پروژه.**
