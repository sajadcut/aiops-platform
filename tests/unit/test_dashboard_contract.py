from pathlib import Path


def test_dashboard_contains_required_operational_capabilities():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    actions = Path("dashboards/approval-actions.js").read_text(encoding="utf-8")
    combined = html + "\n" + js + "\n" + actions
    required = [
        "مرکز فرمان",
        "رخدادهای فعال",
        "در انتظار تأیید",
        "تأییدشده، منتظر اجرا",
        "اجرای موفق",
        "بازیابی‌های تأییدشده",
        "ناقص یا نامشخص",
        "تجربه‌های ثبت‌شده",
        "حافظهٔ تاریخی جایگزین شواهد زنده نیست",
        "موفقیت خودکارسازی",
        "میانگین اطمینان",
        "مراحل رسیدگی و بازیابی",
        "موارد نیازمند اقدام اپراتور",
        "سرویس‌های دارای بیشترین اختلال",
        "رخدادها",
        "فهرست رخدادهای ثبت‌شده",
        "سلامت سرویس‌ها",
        "زیرساخت MCP",
        "VM Edge MCP",
        "دانش کاگنیا",
        "ممیزی و حاکمیت",
        "کنترل‌های حاکمیتی",
        "مجوز امضاشده",
        "X-API-Key",
        "/api/v1/dashboard/summary",
        "/api/v1/dashboard/incidents",
        "/api/v1/dashboard/services",
        "/lifecycle",
        "/evidence",
        "/verification",
        "/memory?limit=5",
        "/api/v1/agents/catalog",
        "/api/v1/health",
        "/workflow/e2e/",
        "binding_complete",
        "ادامه و اجرا",
    ]
    missing = [token for token in required if token not in combined]
    assert not missing, f"Dashboard contract missing: {missing}"
    assert "cognia" in combined.lower()
    assert "حافظهٔ عملیاتی" in combined
    assert "ایجنت‌ها تحلیل و پیشنهاد ارائه می‌کنند" in combined
    assert "تأیید به اقدام مشخص و یک‌بارمصرف محدود است" in combined


def test_dashboard_does_not_embed_demo_or_synthetic_operational_data():
    combined = (
        Path("dashboards/index.html").read_text(encoding="utf-8")
        + Path("dashboards/control-center.js").read_text(encoding="utf-8")
    ).lower()
    for forbidden in ["fake incident", "demo-incident", "mock incident", "array.from({length:18}"]:
        assert forbidden not in combined


def test_service_health_is_durable_not_static_topology():
    api = Path("apps/api/dashboard_incidents.py").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    assert '@router.get("/dashboard/services")' in api
    assert "critical_active" in api
    assert "failed_executions" in api
    assert "failed_verifications" in api
    assert "partial_verifications" in api
    assert "memory_persisted" in api
    assert "serviceState" in js
    assert "topology" not in js.lower()  # dependency graph is not fabricated without durable dependency data


def test_dashboard_summary_tracks_full_governed_lifecycle():
    api = Path("apps/api/dashboard.py").read_text(encoding="utf-8")
    for token in [
        "approvals_consumed",
        "execution_success",
        "execution_failed",
        "execution_blocked",
        "verification_success",
        "verification_failed",
        "verification_partial",
        "verification_inconclusive",
        "memory_persisted",
        "memory_not_persisted",
        "verification_conclusive_rate",
        "execution_success_rate",
    ]:
        assert token in api

def test_incident_refresh_lazy_loads_historical_memory():
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    assert "const [context, evidence, lifecycle, verification] = await Promise.all" in js
    assert "memory: null" in js
    assert "async function loadIncidentMemory" in js
    assert "در حال دریافت حافظهٔ عملیاتی تاریخی" in js
    assert "loadIncidentMemory(S.selected)" in js

def test_dashboard_assets_use_absolute_routes_without_client_redirect_race():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    for asset in (
        "/dashboard/control-center.css",
        "/dashboard/approval-actions.css",
        "/dashboard/control-center.js",
        "/dashboard/approval-actions.js",
    ):
        assert asset in html
    assert "location.replace(location.pathname+'/'" not in html
    assert 'href="control-center.css"' not in html
    assert 'src="control-center.js"' not in html

def test_dashboard_theme_matches_chatbot_and_persists_across_surfaces():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    css = Path("dashboards/control-center.css").read_text(encoding="utf-8")
    actions_css = Path("dashboards/approval-actions.css").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")

    assert 'id="themeToggle"' in html
    assert 'id="themeMoon"' in html
    assert 'id="themeSun"' in html
    assert 'id="themeLabel"' in html
    assert "aiops.chatbot.theme" in html
    assert "aiops.chatbot.theme" in js
    assert "window.matchMedia('(prefers-color-scheme: light)')" in js
    assert "document.documentElement.dataset.theme = theme" in js
    assert "localStorage.setItem(THEME_STORAGE, theme)" in js
    assert "window.addEventListener('storage'" in js
    assert ":root[data-theme=\"light\"]" in css
    assert "--bg:#0B0F14" in css
    assert "--bg:#F6F8FA" in css
    assert "--blue:#5B8DEF" in css
    assert "--blue:#315FAD" in css
    assert ':root[data-theme="light"] .approval-card' in actions_css

