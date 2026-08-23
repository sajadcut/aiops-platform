# AI Ops NeoBankingOperation Platform — NEXT TASK

**Purpose:** این فایل تنها برای مشخص‌کردن کار بعدی پروژه است.

## Current Phase

**COMPLETED — All Phases Done**

## Current Goal

پروژه به‌طور کامل پیاده‌سازی شده است. کار بعدی بستگی به نیازهای واقعی دارد.

## Immediate Task (انتخاب مسیر)

پس از تکمیل کامل پروژه، مسیرهای زیر برای ادامه کار پیشنهاد می‌شود:

### مسیر ۱: اتصال به منابع واقعی (MCP)

**Deliverables:**
- [ ] راه‌اندازی MCP Server برای Zabbix
- [ ] راه‌اندازی MCP Server برای Elasticsearch
- [ ] راه‌اندازی MCP Server برای Prometheus
- [ ] تنظیم `server_url` در MCP Clientها
- [ ] تست `analyze` با داده‌های واقعی

**Acceptance Criteria:**
- MCP Clientها با MCP Serverهای واقعی ارتباط برقرار کنند.
- Context Builder داده‌های واقعی را دریافت کند.

### مسیر ۲: Dockerize کردن پروژه

**Deliverables:**
- [ ] نوشتن `Dockerfile`
- [ ] نوشتن `docker-compose.yml`
- [ ] تست ساخت و اجرا با Docker

**Acceptance Criteria:**
- پروژه با `docker-compose up` بدون خطا بالا بیاید.
- همه APIها در داخل کانتینر قابل دسترسی باشند.

### مسیر ۳: اضافه کردن Dashboard

**Deliverables:**
- [ ] اضافه کردن endpoint `/api/v1/incidents` برای لیست Incidentها
- [ ] ایجاد یک Dashboard ساده (HTML/JS یا React)
- [ ] نمایش آمار: تعداد Incidentها، نرخ موفقیت، Actionهای خودکار

### مسیر ۴: پیاده‌سازی Audit Service

**Deliverables:**
- [ ] مدل `AuditLog` در دیتابیس
- [ ] ثبت تمام رویدادها و تصمیمات
- [ ] endpoint برای مشاهده لاگ‌ها

## Next Step

پس از انتخاب مسیر، فایل‌های مربوطه به‌روزرسانی می‌شوند.