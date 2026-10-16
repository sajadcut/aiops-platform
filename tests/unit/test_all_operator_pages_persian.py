"""Persian-first UI regression across AIOps operator surfaces.

These assertions cover displayed interface copy while preserving provider
codes, raw incident evidence and backend authorization semantics.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASH = ROOT / "dashboards"


def read(name: str) -> str:
    return (DASH / name).read_text(encoding="utf-8")


def test_every_user_facing_html_entrypoint_is_persian_and_rtl():
    for name in ("index.html", "chatbot.html", "incident-command-room.html", "agents.html"):
        html = read(name)
        assert '<html lang="fa" dir="rtl">' in html, name
        assert "فارسی" in html or "مرکز فرمان" in html or "رخداد" in html or "ایجنت" in html


def test_all_control_center_subpages_show_persian_static_copy():
    html = read("index.html")
    for view in ("overview", "incidents", "services", "agents", "mcp", "knowledge", "audit"):
        assert f'data-view="{view}"' in html
    for label in (
        "مرکز فرمان", "رخدادها", "سرویس‌ها", "ایجنت‌ها و تحلیل علت",
        "زیرساخت MCP", "پایگاه دانش", "ممیزی و حاکمیت",
        "همه شدت‌ها", "همه وضعیت‌های سلامت", "مرز ایمنی",
        "ایجنت‌ها تحلیل و پیشنهاد ارائه می‌کنند",
        "دانش در انتظار بازبینی", "ساخت پیش‌نویس دستی",
        "تاریخچهٔ ممیزی", "کنترل‌های حاکمیتی",
        "دانش کاگنیا و حافظهٔ عملیاتی",
    ):
        assert label in html, label
    for obsolete in (
        "All severities", "Search services", "Safety boundary",
        "Agents analyze and recommend", "Pending Knowledge",
        "Human approval boundary", "Governance Controls",
        "The review queue will load here.",
    ):
        assert obsolete not in html, obsolete


def test_actions_and_knowledge_ui_use_persian_without_changing_governance():
    actions = read("approval-actions.js")
    knowledge = read("knowledge-review.js")
    control = read("control-center.js")
    for label in (
        "درخواست تأییدی ثبت نشده", "مجوز تأیید شد؛ اجرا هنوز شروع نشده است",
        "رد درخواست", "تأیید درخواست", "تأیید پرریسک",
        "اتصال مجوز اجرا ناقص است", "با شروع اجرا، مجوز فقط یک‌بار مصرف خواهد شد",
        "تحلیل ایجنت متخصص", "شواهد ناقص",
    ):
        assert label in actions, label
    for label in ("عنوان دانش", "تأیید و انتشار", "انتشار نسخهٔ تأییدشده",
                  "بررسی فعال‌شدن دانش در کاگنیا", "ثبت دانش"):
        assert label in knowledge, label
    assert "faStatus(v || '—')" in control
    assert "faAction(" in control
    assert "['high', 'critical'].includes(risk)" in actions
    assert "['high', 'critical'].includes(lower(approval.risk_level))" in actions
    assert "approval_changed_or_binding_unverified" in actions
    assert "checkpoint === 'paused'" in actions
    assert "checkpoint === 'completed'" in actions
    assert "/api/v1/approvals/" in actions
    assert "JSON.stringify({reason})" in actions


def test_chatbot_is_persian_first_but_preserves_api_keys_and_raw_evidence():
    html = read("chatbot.html")
    js = read("chatbot.js")
    ui = read("chatbot-ui.js")
    brief = read("decision-brief.js")
    for label in ("دستیار هوشمند عملیات نئوبانکینگ", "ورود امن",
                  "تاریخچهٔ گفت‌وگوها", "داشبورد", "اتصال API برقرار است"):
        assert label in html, label
    for label in ("پیشنهاد اقدام", "دستیار عملیات", "سلامت سرویس",
                  "تأیید و اجرای کنترل‌شده"):
        assert label in js, label
    for label in ('copy.textContent = "کپی"', '["وضعیت"', '["حافظه"',
                  '["درخواست"', '["مولفه"'):
        assert label in ui, label
    assert "return 'fa';" in brief
    assert "return 'fa';" in read("approval-actions.js")
    # Technical provider keys and source JSON remain machine-readable.
    assert 'data-recommendation-lang="en"' in read("approval-actions.js")
    assert "JSON.stringify(data, null, 2)" in ui
    assert 'sessionStorage.setItem(KEY_STORAGE' in js
    assert "JSON.stringify({confirm: value})" in js
    assert '"X-API-Key"' in read("chatbot-transport.js")
