"""Cognia card source-code and decision-brief contract regressions."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_cognia_ui_never_unconditionally_claims_similar_experience():
    source = (ROOT / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert "کاگنیا تجربه‌های مشابهی پیدا کرده" not in source
    assert "const items=arr(k.items),accepted=items.length;" in source
    assert "سند Cognia #" in source
    assert "document_kind==='historical_incident_experience'" in source
    assert "تأثیر این اسناد بر تصمیم نهایی" in source
    assert "امتیاز تطبیق جست‌وجو" in source


def test_relevance_gate_still_rejects_cross_service_documents():
    from apps.context_service.knowledge_relevance import filter_service_knowledge
    docs, audit = filter_service_knowledge(
        [{"source_id": "cognia:1:2:3:4",
          "content": "Service: nginx\nNginx restart protocol"}],
        expected_service="gfpapi",
    )
    assert docs == []
    assert audit["rejected_count"] == 1
    assert audit["rejected"][0]["declared_services"] == ["nginx"]
