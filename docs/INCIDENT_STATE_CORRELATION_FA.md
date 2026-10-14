# Incident state correlation — گزارش SRE مبتنی بر شواهد

## مسئله‌ای که اصلاح شده

در رخداد GFPAPI، متن هشدار اولیهٔ Zabbix وضعیت `Down / inactive` را گزارش کرده است اما استعلام ثبت‌شدهٔ VM MCP وضعیت `active/running` را نشان می‌دهد. دو گزاره لزوماً تناقض زمانی نیستند: ممکن است زمان متفاوتی داشته باشند، هشدار Stale باشد یا سرویس از نظر systemd بالا ولی API ناسالم باشد.

بخش ۰۱ اکنون این **اختلاف منابع** را به‌جای «به بررسی بیشتر نیاز دارد» نمایش می‌دهد و برای هر منبع زمان مشاهده و شناسهٔ Evidence را نگه می‌دارد. اگر زمان وقوع Event در payload اصلی ثبت نشده باشد، زمان دریافت AIOps را به‌جای وقوع Event جا نمی‌زند.

## پیاده‌سازی

- `apps/incident_evidence_correlation.py`: تحلیل Deterministic و فقط خواندنی، براساس تطبیق سرویس، IP میزبان، منبع و زمان دقیق؛ بدون استفاده از LLM به‌عنوان شاهد.
- `apps/decision_brief.py`: اضافه‌شدن `state_correlation` و تغذیهٔ `operator_explanation` از یافتهٔ واقعی اختلاف وضعیت. فیلدهای Approval و Execution Binding تغییری نکرده‌اند.
- `apps/incident_explanation.py`: تیتر تخصصی بر جملهٔ عمومی اولویت دارد؛ Process Check منفی به معنی توقف پردازش `.NET` یا MainPID نیست.
- `dashboards/incident-command-room.js`: در بخش ۰۱، کارت زبیکس و VM MCP، وضعیت HTTP، Event Time در برابر Received Time، و سه آزمون تفکیک‌کننده. وضعیت بررسی مجدد VM در همان صفحه و بدون اجرای Start/Restart نشان داده می‌شود.

## تفسیر و حدود اثبات

| شواهد | نتیجهٔ مجاز | نتیجهٔ غیرمجاز |
| --- | --- | --- |
| Zabbix Down و VM MCP Running | اختلاف وضعیت گزارش‌شده توسط دو منبع | سرویس قطعاً بازیابی شده، هشدار False Positive است |
| دو مشاهدهٔ مستقیم VM MCP با زمان معتبر (Stopped سپس Running) | تغییر وضعیت مشاهده‌شدهٔ systemd | علت بازیابی یا عامل Restart مشخص است |
| systemd Running، HTTP Unhealthy | پردازش از دید systemd بالا ولی آزمون HTTP ناموفق | API سالم است |
| Process Check با نام gfpapi منفی | نام مورد جست‌وجو دیده نشده | پردازش dotnet یا MainPID قطعاً وجود ندارد |
| Zabbix Recovery | منبع مانیتورینگ رفع هشدار را اعلام کرده | AIOps اقدامی اجرا کرده یا RCA تأیید شده |
| JSON Syntax Valid همراه Startup Failure | Syntax بررسی‌شده، اما Runtime همچنان مسئله دارد | Dependency/Configuration Semantic/Startup Healthy |
| داده از VM دیگر | رد انتساب و عدم تلفیق | تطبیق صرفاً بر مبنای نام یکسان سرویس |

اطلاعات هر فرضیه با `status=unverified` یا `supported_not_confirmed` و بدون درصد اطمینان ساختگی ثبت می‌شوند. *Cognia* و جمع‌بندی Agentها به‌تنهایی شاهد وقوع تغییر وضعیت نیستند.

## اقدام‌های اولویت‌دار در همین رخداد

۱. دریافت Event Time، Trigger Expression، Item History و Recovery Event واقعی از Zabbix.

۲. تطبیق ExecMainStartTimestamp، MainPID، RestartCount و Journal سرویس از VM MCP در همان بازه.

۳. پس از تنظیم پورت و Endpoint واقعی سرویس، بررسی Listening Port، TCP و HTTP Health با مجوز Read-only.

نبود Health Endpoint با «سالم بودن HTTP» یکسان نیست. مشاهدهٔ فعلی Running هم از آخرین زمان جمع‌آوری داده نباید به زمان حال تعمیم داده شود.

## تست و استقرار

تست‌های Unit سناریوهای اختلاف بدون Timestamp، تقدم و تأخر معتبر، Timestamp با دقت دقیقه، دو مشاهدهٔ VM، VM اشتباه، HTTP ناسالم، Process Name، Recovery مانیتورینگ و محدودیت Syntax را پوشش می‌دهند. تست Node/Chromium اجرای واقعی Renderer بخش ۰۱ را کنترل می‌کند.

از نسخهٔ جدید `main` روی AIOps API و Dashboard استفاده کنید. برای این تغییر Migration دیتابیس لازم نیست. برای اثبات در محیط واقعی، اجرای مجدد روی Zabbix، VM MCP، Journal و Health Endpoint: **REAL ENV REQUIRED**. این PR هیچ اجرای عملیاتی، خواندن خودکار جدید یا دورزدن Approval ایجاد نمی‌کند.
