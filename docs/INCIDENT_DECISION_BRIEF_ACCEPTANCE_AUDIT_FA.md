# ممیزی بندبه‌بند AIOps Incident Decision Brief

**مبنای بررسی:** الزامات «پرامت پیاده‌سازی AIOps Incident Decision Brief» (۴۰۴ خط) و کد شاخه main به‌همراه اصلاحات این PR، تاریخ ۱۱ اکتبر ۲۰۲۶. «پیاده‌سازی‌شده» به معنی وجود کد و تست قابل‌ردیابی است؛ به معنی تایید عملیاتی Production نیست.

**راهنمای وضعیت:** ✅ در کد/تست موجود؛ ◐ مشروط به داده واقعی یا ناقص؛ ⛔ گپ اثبات‌شده؛ 🌐 REAL ENV REQUIRED. هیچ نتیجهٔ شبیه‌سازی‌شده PASS عملیاتی نیست.

## ۱) معماری و تطبیق با سیستم موجود

| الزام | وضعیت | ردیابی / محدودیت |
|---|---|---|
| Incident Lifecycle و E2E Workflow | ✅ | `apps/orchestrator/e2e_graph.py`، `apps/orchestrator/workflow_store.py` |
| Triage، RCA و متخصص VM/Network/Application/Infrastructure | ◐ | `analysis_results` و `triage_result` از Checkpoint؛ Agentهای فاقد سابقه اجرا موفق معرفی نمی‌شوند. جزئیات مأموریت/ابزار فقط اگر ذخیره شده باشد |
| Remediation Planner، Evaluator و Verification | ✅ | `apps/operator_summary.py`، `apps/decision_brief.py`، `apps/verification_service` |
| MCP Client/Server و Evidence provenance | ◐ | Evidenceهای پایدار و `source_observation` قابل گزارش‌اند؛ در Traceهای فاقد شناسه Server/Tool، جزئیات مجهول می‌مانند |
| Cognia RAG و Knowledge Source | ◐ | داده ذخیره‌شده `knowledge_results`، نه جست‌وجوی مجدد؛ بعضی مشخصات سند از Cognia در قرارداد اولیه وجود ندارند |
| Operational Memory و pgvector | ✅ | `apps/memory_service`؛ رخداد تاریخی از شاهد زنده جداست |
| Approval، RBAC، Audit، Timeline | ✅ | `apps/approval_service/binding.py`، `apps/api/incident_resources.py`؛ تأیید و اجرای عملیات مسیر جدا دارد |
| Operator Summary و Localization | ✅ | خلاصه قطعی مستقل از LLM، `apps/decision_brief_narrative.py`، RTL/LTR |
| عدم ایجاد Workflow موازی یا اجرای ابزار هنگام مشاهده | ✅ | دو GET read-only با `read:incident`؛ هیچ Tool/RAG/Execution در سازنده گزارش اجرا نمی‌شود |
| Correlation ID/Trace/Evidence/Knowledge/Memory | ◐ | هر شناسه فقط اگر در داده Persisted موجود باشد؛ عدم وجود Trace ID هیچ‌گاه جعل نمی‌شود |

## ۲) داشبورد و خلاصه مدیریتی

| الزام | وضعیت | توضیح |
|---|---|---|
| تب برجسته کنار Decision و بازشدن خودکار برای Pending Approval | ✅ | `dashboards/decision-brief.js` |
| Incident، Service، Severity، Status | ✅ | `incident_summary` |
| Host، VM، Namespace، Cluster | ◐ | از `observed_state` و `incident.context`، فقط در صورت موجودبودن |
| زمان شروع و مدت سپری‌شده | ✅ | `started_at`، `elapsed_seconds`؛ زمان غیرمعتبر Unknown |
| نتیجه RCA و وضعیت قطعیت | ✅ | Operator Summary؛ وضعیت قطعی/محتمل/نامشخص |
| RCA Confidence / Evaluator / Agreement مستقل | ✅ | `rca_assessment` و توضیح تفاوت در UI؛ مقادیر غایب Unknown |
| تعداد Evidence معتبر و وضعیت سلامت منبع | ✅ | `valid_evidence_count`، `monitoring_sources`؛ Observation پایش به‌عنوان شاهد مثبت شمرده نمی‌شود |
| پیشنهاد واقعی Action، Risk و Approval | ✅ | از ExecutionRequest / Approval موجود؛ بدون ساخت Action توسط مدل |
| هشدارها و توضیح دلیل تصمیم | ◐ | Evidence/Gap/Citation + Action Plan؛ ارتباط علّی بدون Citation «تأیید نشده» |
| UX مصرف در ۳۰–۶۰ ثانیه | 🌐 | چیدمان خلاصه و Collapse موجود؛ آزمون زمان واقعی اپراتور/مرورگر Production انجام نشده |

### B) عملکرد Agentها

| الزام | وضعیت | توضیح |
|---|---|---|
| نام، اجرا/ناموفق/ناقص/Skip | ✅ | `_agents` به وضعیت ثبت‌شده و Failure Result متکی است |
| مأموریت، Tool، Trace، Outcome، Confidence | ◐ | تنها اگر خروجی Agent حاوی این فیلدها باشد |
| Evidence Reference و اختلاف‌نظر | ✅ | `evidence_refs`، `conflicting_evidence_refs`، `missing_evidence` |
| اطمینان RCA، Evaluator و میزان توافق | ✅ | مستقل و تفکیک‌شده در UI |

### C) MCP و شواهد زیرساخت

| الزام | وضعیت | توضیح |
|---|---|---|
| Server، Tool، موفق/ناموفق، زمان و Freshness | ✅ | شناسایی بر اساس منبع پایدار و `tool_failed` در نتیجه داخلی |
| پیش/پس از Remediation | ◐ | `phase` اگر هنگام Collection ثبت شده؛ در غیر این صورت Unknown |
| systemd، Process، TCP، Listener، Config، Metric و Log | ◐ | نمایش فیلدهای واقعی allowlist؛ عدم انتشار Journal خام یا Credential |
| SSH access، Disk/CPU/Memory | ◐ | فقط اگر در فیلدهای Evidence/observed ذخیره شده باشند |
| قطعی Prometheus، Elastic یا Zabbix | ✅ | `source_observation` با `unavailable/error/queried` و هشدار صریح |
| HTTP 200 همراه Tool Failure | ✅ | نتیجه داخلی بررسی می‌شود؛ صرف موفقیت انتقال HTTP موفقیت عملیات نیست |

### D) Cognia RAG

| الزام | وضعیت | توضیح |
|---|---|---|
| Available / Empty / Failed / Not Queried | ✅ | از `knowledge_status` پایدار |
| KB ID، Knowledge/Revision/Source ID و Relevance | ✅ | فقط فیلدهای ثبت‌شده |
| عنوان، نوع، خلاصه و اطلاعات تاریخی | ◐ | عنوان/متادیتا در صورت وجود؛ `excerpt` زبان اصلی و به‌وضوح Original است |
| بازیابی در برابر استفاده مؤثر در RCA | ✅ | `not_verified` مگر Citation در Agent معتبر؛ استناد «استفاده در تصمیم نهایی» را به‌تنهایی ثابت نمی‌کند |
| مواردی با چند سند اما بدون Citation | ✅ | `retrieved_count` و `use_status=not_verified` |

### E) Operational Memory

| الزام | وضعیت | توضیح |
|---|---|---|
| Memory ID / Incident قبلی / Similarity | ✅ | از `memory_results` ذخیره‌شده |
| اقدام، Outcome، Verification قبلی | ✅ | فقط رکورد تاریخی |
| شرایط تعمیم، نکته قابل استفاده | ◐ | وضعیت Root Cause/نسخه سرویس و هشدار تعمیم؛ استنتاج خودکار علت ممنوع |
| نقش Memory در تصمیم فعلی | ◐ | Citation Agent قابل نمایش است، ولی تأثیر نهایی بدون Trace معتبر اثبات نمی‌شود |
| تفکیک Cognia و Memory | ✅ | قرارداد و دو تب/بخش مستقل |

## ۳) جمع‌بندی هوشمند فارسی

| الزام | وضعیت | توضیح |
|---|---|---|
| LLM تنظیم‌شده، از جمله Dotin در صورت فعال‌بودن | ✅ / 🌐 | ماژول و API پیاده‌سازی شده؛ اتصال عملی به مدل سازمانی REAL ENV REQUIRED |
| ۱۱ بخش شرح، یافته، فرضیه، دانش، Gap، علت، اقدام، دلیل، Preconditions، Verification، توصیه | ✅ | `SECTIONS` ثابت و schema validation |
| Citation معتبر و جلوگیری از فرمان جدید | ◐ | IDهای Citation اعتبارسنجی ساختاری، متن‌ها به‌عنوان «مشورتی»؛ درستی معنایی هر گزارهٔ تولیدی نیازمند بازبینی انسان است |
| خطا و Timeout، Fallback غیر-JSON | ✅ | ۱۲ ثانیه، Cache محدود، متن قطعی مستقل، Retry کنترل‌شده |
| Toggle زبان واقعی و ماندگاری انتخاب | ✅ | localStorage و Node runtime test برای RTL/LTR |
| جداسازی Incident/Language در درخواست‌های async | ✅ | Snapshot check و request key؛ پاسخ دیررس نمی‌تواند رخداد دیگری را جایگزین کند |

## ۴) Approval Decision

| الزام | وضعیت | توضیح |
|---|---|---|
| Action/Tool/Target/Environment/Risk/Runbook | ✅ | داده تأیید واقعی + Digest غیرحساس و وضعیت Binding |
| Blast Radius، Risk of inaction، Preconditions، Rollback و Verification Plan | ◐ | فقط اگر Plan آن فیلدها را ذخیره کرده باشد؛ Guess ممنوع |
| Approve، Reject، Resume & Execute | ✅ | لینک به پنل Governance موجود؛ Brief هیچ POST ندارد |
| Request More Evidence | ◐ | دکمه‌ای در Brief ایجاد نشده زیرا Backend اختصاصی این عملیات اثبات نشده است |
| Raw Evidence و Timeline | ✅ | هدایت به پنل اصلی Evidence/Audit |
| جلوگیری از اجرا بدون Approval و High Risk | ✅ | Binding و مصرف یک‌باره مجوز در Backend موجود؛ تست‌های `tests/security` و `tests/unit/test_runtime_guard_approval_revocation.py` |
| Binding به Incident/Action/Tool/Target/Runbook | ✅ | `apps/approval_service/binding.py` |
| Binding صریح به Evidence Snapshot و نسخه Plan و Reapproval بر اثر Drift | ✅ / ◐ | در Approvalهای **جدید** Durable Workflow و Direct API اثرانگشت Plan/Agent Results/Checkpoint و تمام Evidenceهای پایدار ثبت می‌شود و در Resume و /execute پیش از مصرف مجوز تطبیق و در صورت تغییر لغو می‌شود. Approvalهای Legacy متعلق به E2E با ریسک high/critical و بدون Digest هنگام Claim رد و برای re-approval لغو می‌شوند؛ Approvalهای مستقل Chatbot و سایر Scopeهای قدیمی تابع کنترل جداگانه خود هستند |

## ۵) پس از اجرا

| الزام | وضعیت | توضیح |
|---|---|---|
| Approver، Action، Target، نتیجه اجرا و وضعیت Verification | ✅ | فقط از Operator Summary/Checkpoint/Audit |
| تغییرات قبل/بعد و Metrics | ◐ | اگر Verification مقایسه‌های ثبت‌شده داشته باشد |
| Fail یا Success با Incident Status | ✅ | تفکیک موفقیت فرمان از Recovery؛ وضعیت Incident در خلاصه |
| Memory ID و Knowledge Review Draft | ✅ | فقط برای Recovery تأییدشده با Memory و Review واقعی |
| استقلال Knowledge Publication از Execution Approval | ✅ | سرویس Knowledge Review مجزا و کنترل‌های مربوط به خودش |

## ۶) UI/UX

| الزام | وضعیت |
|---|---|
| RTL فارسی / LTR انگلیسی، فونت و Dark Mode هماهنگ | ✅ در کد؛ بررسی بصری دستگاه واقعی 🌐 |
| Responsive، Summary بالا، Expand/Collapse | ✅ |
| Timeline، Provenance، هشدار و کپی کامل گزارش | ✅ |
| Raw Evidence و کنترل‌های امن | ✅ |
| Loading، Error، Legacy Unknown و قطعی MCP/LLM | ✅ |
| بارگذاری مجدد Incident بعد از Approval/Resume | ✅ از Wrapperهای موجود؛ E2E مرورگر واقعی 🌐 |

## ۷) Backend / Contract / Security

| الزام | وضعیت | توضیح |
|---|---|---|
| قرارداد Versioned با تمام بخش‌های اصلی | ✅ | `decision-brief.v1`؛ ساختارهای Incident/Agents/MCP/Cognia/Memory/RCA/Approval/Execution/Verification/Localization |
| یک نمای سازگار از Incident/Approval/Checkpoint | ✅ | سازنده Operator Summary و Brief در همان SQLAlchemy Session |
| Snapshot/Version و تازگی Workflow | ✅ / ◐ | History immutable جدید از رویدادهای واقعی Approval/Execution/Verification با JSONB پاک‌سازی‌شده و خواندن RBAC؛ Checkpoint و Evidence در قفل مشترک Incident هنگام Claim دوباره اعتبارسنجی می‌شوند. Snapshotهای قبل از استقرار به‌طور مصنوعی بازسازی نمی‌شوند |
| Redaction، RBAC، خطا و Unknown | ✅ | `redact`، `read:incident` و fallback |
| عدم اجرای Workflow/Tool/RAG هنگام بازشدن Brief | ✅ | GET فقط خواندنی؛ GET جداگانه Narrative فقط LLM نمایشی را فراخوانی می‌کند |
| Cache/Timeout/کنترل هزینه LLM | ✅ | Cache حداکثر ۱۰۰ گزارش در پردازش؛ زمان انتظار محدود و خروجی bounded |
| Audit تغییر تصمیم / اجرا | ✅ | از Audit Event ذخیره‌شده؛ خود گزارش Audit Event جدید ثبت نمی‌کند |

## ۸) ماتریس ۱۸ سناریوی پذیرش

| شماره | سناریو | وضعیت واقعی |
|---|---|---|
| ۱ | nginx با شواهد کامل و پیشنهاد | ✅ unit/synthetic؛ 🌐 Live |
| ۲ | قطع بخشی از MCP/Monitoring | ✅ unit/synthetic؛ 🌐 Live |
| ۳ | Cognia نتیجه مرتبط | ✅ unit/synthetic؛ 🌐 Live |
| ۴ | Cognia جست‌وجوی خالی | ✅ unit/synthetic |
| ۵ | Cognia بازیابی شده ولی در RCA استفاده نشده | ✅ unit/synthetic |
| ۶ | Agentهای متناقض | ✅ unit/synthetic |
| ۷ | RCA نامطمئن و Remediation قابل بررسی | ✅ unit/synthetic |
| ۸ | Evidence کهنه یا Snapshot drift | ✅ Freshness، تطبیق زیر قفل و تست واقعی دیتابیس؛ high/critical legacy در E2E بدون Digest رد می‌شود؛ ◐ اتصال Production |
| ۹ | High Risk نیازمند Approval | ✅ تست Governance موجود؛ 🌐 Live |
| ۱۰ | Reject و عدم اجرا | ✅ در تست‌های Backend؛ 🌐 Live |
| ۱۱ | Approve، اجرا و Verification موفق | ✅ در تست‌های Backend؛ 🌐 Live |
| ۱۲ | اجرای ناموفق/Verification Failed | ✅ unit و backend؛ 🌐 Live |
| ۱۳ | Memory و Knowledge Review Draft | ✅ قرارداد/تست؛ 🌐 Live |
| ۱۴ | فارسی/English، بدون JSON با عنوان فارسی | ✅ tests/unit و Node UI runtime؛ 🌐 Browser |
| ۱۵ | قطع LLM و fallback | ✅ unit |
| ۱۶ | RBAC، Audit، Secret و عدم اجرای بدون Approval | ✅ unit/integration/security؛ 🌐 OIDC |
| ۱۷ | Reload و Resume Workflow | ◐ Backend checkpoint tests؛ 🌐 browser/live |
| ۱۸ | رگرسیون Dashboard/Chatbot | ✅ GitHub quality/chatbot/container CI؛ 🌐 Production smoke |

## ۹) تحویل، اجرای تست و گپ‌های قابل‌بستن

تست کد و نمونه‌های ساختگی، جای تست محیط واقعی نیست. از ریشه پروژه در PowerShell:

```powershell
python -m pytest -q tests/unit/test_decision_brief.py tests/unit/test_decision_brief_narrative.py tests/unit/test_decision_brief_browser_runtime.py tests/integration/test_decision_brief_ui_api.py
python -m pytest -q tests
```

**گپ‌های باقی‌مانده:** (۱) سیاست استفاده از Approvalهای Legacy کم‌ریسک و صدور مجوز جدید در فرایند عملیاتی (high/critical در محدوده E2E اکنون fail-closed هستند)؛ (۲) نبود Snapshotهای تاریخی مربوط به پیش از استقرار این Migration؛ (۳) Provenance دقیق Trace/Tool/Knowledge در صورت Persist نشدن در مبادی داده؛ (۴) تست واقعی Chrome/Firefox، اتصال Dotin/Cognia/MCP/pgvector و Remediation + Rollback Production؛ (۵) راستی‌آزمایی معنایی هر گزاره مدل؛ (۶) تست زمان ۳۰–۶۰ ثانیه‌ای UX در محیط واقعی.

**نکتهٔ پذیرش:** تا بسته‌شدن گپ‌های امنیتی و اجرای آزمون‌های REAL ENV REQUIRED، اعلام «Production accepted» یا جایگزین‌کردن بازبینی اپراتور با تصمیم خودکار مجاز نیست.
