from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_is_single_live_control_center():
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/control-center.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/control-center.css").read_text(encoding="utf-8")

    assert "<title>مرکز فرمان AIOps</title>" in html
    assert "مرکز فرمان" in html
    assert "زیرساخت MCP" in html
    assert "سرویس‌های دارای بیشترین اختلال" in html
    assert "موارد نیازمند اقدام اپراتور" in html
    assert "فهرست رخدادهای ثبت‌شده" in html
    assert "ممیزی و حاکمیت" in html
    assert "/api/v1/dashboard/summary" in js
    assert "/api/v1/dashboard/incidents?limit=100" in js
    assert "/api/v1/dashboard/services?limit=100" in js
    assert "/api/v1/health" in js
    assert "/evidence?limit=100" in js
    assert "/lifecycle" in js
    assert "/verification" in js
    assert "/api/v1/agents/catalog" in js
    assert "/api/v1/agents/metrics" in js
    assert "fake" not in js.lower()
    assert "--surface" in css
    assert ".command-grid" in css
    assert ".incident-layout" in css


def test_incident_workbench_defaults_to_last_24h_including_resolved_and_shows_unambiguous_local_time():
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")

    assert 'value="__active__">فقط رخدادهای فعال' in html
    assert 'value="" selected>همه رخدادها' in html
    assert 'value="recent" selected>۲۴ ساعت اخیر' in html
    assert "فهرست رخدادهای ثبت‌شده" in html
    assert "function incidentTimeInfo" in html
    assert "i.started_at || i.created_at" in html
    assert "Intl.DateTimeFormat().resolvedOptions().timeZone" in html
    assert "matchesIncidentStatusScope" in html
    assert "scope === '__active__'" in html
    assert "رخدادی با این فیلترها پیدا نشد" in html


def test_dashboard_assets_and_agent_route_are_served_by_fastapi():
    source = (ROOT / "apps/api/main.py").read_text(encoding="utf-8")
    assert '@app.get("/dashboard/control-center.css"' in source
    assert '@app.get("/dashboard/control-center.js"' in source
    assert 'return FileResponse(_DASHBOARD_DIR / "index.html")' in source


def test_legacy_agent_url_has_compatibility_redirect_only():
    html = (ROOT / "dashboards/agents.html").read_text(encoding="utf-8")
    assert "location.replace("/dashboard")" in html
    assert "ایجنت‌ها و تحلیل علت" in html


def test_command_center_is_fully_persian_rtl_without_changing_provider_keys():
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/control-center.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/control-center.css").read_text(encoding="utf-8")
    assert '<html lang="fa" dir="rtl">' in html
    assert 'data-view="overview"' in html
    for label in (
        "رخدادهای فعال", "در انتظار تأیید", "تأییدشده، منتظر اجرا",
        "اجرای موفق", "بازیابی‌های تأییدشده", "تجربه‌های ثبت‌شده",
        "میانگین اطمینان", "مراحل رسیدگی و بازیابی",
        "سلامت اجزای سامانه و اتصال‌ها", "توزیع شدت رخدادها",
        "رویدادهای اخیر سامانه مدیریت", "مستندات API"
    ):
        assert label in html, label
    for label in (
        "در انتظار تأیید", "راستی‌آزمایی ناموفق", "نتیجه در حافظه ثبت نشده",
        "سرویس نامشخص", "نیازمند تأیید انسانی", "در دسترس نیست",
        "شواهد سامانه پایش", "نسخه پایگاه‌داده"
    ):
        assert label in js, label
    assert "/* Persian Command Center interface */" in css
    assert '[dir="rtl"] .sidebar' in css
    assert '[dir="rtl"] .view[data-view="overview"] .kpi-top' in css
    # Provider API values are intentionally NOT changed by the translation.
    assert "Number(s.critical_active) > 0" in js
    assert "lower(i.approval_status) === 'pending'" in js
    assert "x.verification_success" in js
    assert "x.memory_persisted" in js
