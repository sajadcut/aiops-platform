from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_exposes_governed_approval_and_resume_actions():
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/approval-actions.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/approval-actions.css").read_text(encoding="utf-8")

    assert 'approval-actions.css' in html
    assert 'approval-actions.js' in html
    assert '/api/v1/approvals/' in js
    assert '/approve' in js
    assert '/reject' in js
    assert 'دلیل رد درخواست' in js
    assert 'JSON.stringify({reason})' in js
    assert 'تأیید پرریسک' in js
    assert 'هنوز عملیاتی انجام نخواهد شد' in js
    assert 'ادامه و اجرا' in js
    assert '/api/v1/workflow/e2e/' in js
    assert '/resume' in js
    assert 'binding_complete' in js
    assert 'فقط یک‌بار مصرف خواهد شد' in js
    assert 'مجوز امضاشده' in js
    assert '/api/v1/execute' not in js  # Dashboard cannot bypass the durable workflow runtime.
    assert '.approval-btn.approve' in css
    assert '.approval-btn.reject' in css
    assert '.approval-btn.execute' in css
    assert '.execution-consumed' in css


def test_fastapi_serves_approval_assets():
    source = (ROOT / "apps/api/main.py").read_text(encoding="utf-8")
    assert '@app.get("/dashboard/approval-actions.css"' in source
    assert '@app.get("/dashboard/approval-actions.js"' in source


def test_critical_risk_requires_secondary_confirmation_before_approval_and_resume():
    from pathlib import Path
    source = Path("dashboards/approval-actions.js").read_text(encoding="utf-8")
    assert "['high', 'critical'].includes(risk)" in source
    assert "['high', 'critical'].includes(lower(approval.risk_level))" in source

def test_operator_dashboard_does_not_resume_a_completed_incident():
    js = (ROOT / "dashboards/approval-actions.js").read_text(encoding="utf-8")
    assert "const fresh = await api(" in js
    assert "checkpoint === 'completed'" in js
    assert "checkpoint === 'paused'" in js
    assert "/approvals/${encodeURIComponent(approval.approval_id)}/execute" in js
    assert "approval_changed_or_binding_unverified" in js
