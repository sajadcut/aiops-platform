# رفع خطای ۵۰۳ و گزارش Fallback در اجرای محلی

## تشخیص از لاگ ۲۰۲۶-۱۰-۱۱

اجرای `start-all.ps1` موفق به بالا آوردن API روی پورت ۸۰۰۰ و VM MCP روی ۹۱۰۵ شده است، اما سلامت لایو `/api/v1/health/live` **به معنی سازگاری Schema نیست**. لاگ نشان می‌دهد:

- `expected_heads = ['l9m0n1o2p3q4']` و `current_heads = ['k8h9i0j1k2l3']`.
- دریافت سیگنال Zabbix، خلاصه داشبورد و برخی منابع Incident به‌طور عمدی در این حالت با `DATABASE_MIGRATION_DRIFT` و HTTP 503 مسدود می‌شوند؛ با غیرفعال‌کردن validation نباید این کنترل را دور زد.
- Zabbix MCP و VM MCP پاسخ می‌دهند ولی Prometheus MCP و Elasticsearch Agent Builder قابل اتصال نیستند و Cognia Health پاسخ ۵۰۰ دارد. این‌ها **از mismatch دیتابیس مستقل‌اند** و به آدرس، شبکه و خود سرویس‌های خارجی مربوط‌اند.
- LLM گزارش تصمیم در نمونه Incident با ۲۹ Evidence به `fallback(brief_too_large)` برگشته بود؛ علاوه بر طراحی گزارش پایدار، projection جدید صرفاً خلاصه حاوی Source ID و ریسک و وضعیت را به مدل می‌فرستد تا از سربار متن خام جلوگیری شود. خطای پیکربندی یا اعتبارسنجی مدل همچنان fallback امن دارد.

## اصلاح قبل از اجرا (PowerShell، روی رایانه توسعه)

**توقف برنامه، بکاپ واقعی و سپس Migration الزامی است.** `start-all.ps1` اکنون به صورت read-only سازگاری نسخه Alembic با دیتابیس را قبل از بالا آوردن API بررسی می‌کند. اگر ناسازگاری باشد، با راهنمای دقیق خارج می‌شود؛ هیچ Migration خودکاری اعمال نمی‌کند.

```powershell
cd <PATH_TO_YOUR_AIOPS_REPOSITORY>
git pull --ff-only origin main
.\stop-all.ps1

# Back up PostgreSQL first and verify that the backup is restorable.
# Then run the repository migration on the intended database:
.\.venv\Scripts\python.exe -m alembic -c database/migrations/alembic.ini current
.\.venv\Scripts\python.exe -m alembic -c database/migrations/alembic.ini upgrade head
.\.venv\Scripts\python.exe -m alembic -c database/migrations/alembic.ini current

.\start-all.ps1
```

قبل از اجرای Migration، حتماً `DATABASE_URL` و در صورت وجود `ALEMBIC_DATABASE_URL` را از نظر اشاره به **دیتابیس درست** بررسی کنید؛ رمزها را در خروجی کپی نکنید. اجرای `upgrade head` روی دیتابیس مشترک یا Production نیازمند پنجره تعمیرات، بکاپ بازیابی‌پذیر و هماهنگی DBA است. **`stamp head` یا `downgrade` راه‌حل این اختلاف نیست.**

برای بررسی مستقل و read-only بدون شروع سرویس‌ها:

```powershell
.\.venv\Scripts\python.exe -m scripts.check_database_migrations
```

سپس وضعیت `http://127.0.0.1:8000/api/v1/health/ready` را بررسی کنید؛ اگر هنوز خطا دارد، dependencyهای بیرونی را به‌ترتیب آزمایش کنید.

## پذیرش

- پیش از Migration: preflight خروجی `DATABASE_MIGRATION_DRIFT` و وضعیت خطای ۳ می‌دهد؛ هیچ سرویس جدیدی راه‌اندازی نمی‌شود.
- بعد از Migration: `DATABASE_MIGRATION_OK`، اجرای مجدد `start-all.ps1`، و نبود `DATABASE_MIGRATION_DRIFT` در درخواست‌های Zabbix/Dashboard.
- Cognia/Prometheus/Elasticsearch فقط زمانی OK می‌شوند که سرویس‌های مربوط واقعاً قابل اتصال و سالم باشند. هیچ Mock یا نادیده‌گیری Health Check جایگزین آن نمی‌شود.
- گزارش هوشمند برای Incidentهای پرشاهد، projection بودجه‌بندی‌شده با شمارنده منبع و ارجاع Evidence دریافت می‌کند؛ متن گزارش Model فقط در صورت موفقیت LLM و Citation Validation نمایش داده می‌شود.
- عملیات VM همچنان به مجوز مستقل، اعتبارسنجی ریسک و اجرای یک‌بارمصرف وابسته است.

همچنان نیاز به **تأیید در محیط واقعی** وجود دارد: نتیجه اجرای Migration روی پایگاه داده کاربر، سرویس‌های خارجی و خود مدل LLM با CI پروژه قابل اثبات نیست.
