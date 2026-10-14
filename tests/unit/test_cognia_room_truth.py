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


def _render_cognia(knowledge, assertions):
    """Drive the actual JS Command Room through the existing Node DOM harness."""
    import json
    import shutil
    import subprocess

    script_file = (ROOT / "tests/unit/test_technical_investigation_browser.py").read_text(encoding="utf-8")
    start = script_file.index('    script = r"""') + len('    script = r"""')
    end = script_file.index('"""', start)
    script = script_file[start:end]
    assert "  const report={" in script
    script = script.replace("  const report={", "  const report={cognia_knowledge:" +
                            json.dumps(knowledge, ensure_ascii=False) + ",", 1)
    marker = "  const page=el('#ic-technical-report').innerHTML;"
    assert marker in script
    script = script[:script.index(marker)] + assertions + "\n})();\n"
    proc = subprocess.run([shutil.which("node"), "-e", script], cwd=ROOT,
                          capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr


def test_empty_and_filtered_cognia_cards_using_real_ui_runtime():
    import shutil
    import pytest
    if not shutil.which("node"):
        pytest.skip("Node unavailable")
    _render_cognia(
        {"status": "empty", "retrieved_count": 0, "accepted_count": 0, "items": []},
        """  assert.match(el('#ic-cognia').innerHTML,/نتیجهٔ مرتبط و قابل‌استنادی/);
  assert.match(el('#ic-cognia-count').textContent,/۰ مرتبط/);
  assert.doesNotMatch(el('#ic-cognia').innerHTML,/تجربه‌های مشابهی پیدا کرده/);"""
    )
    _render_cognia(
        {"status": "filtered_empty", "accepted_count": 0, "rejected_count": 1,
         "rejected_examples": [{"source_id": "cognia:1:11:12:13",
                                "reason": "document_service_conflicts_with_incident",
                                "declared_services": ["nginx"]}], "items": []},
        """  assert.match(el('#ic-cognia-count').textContent,/۰ مرتبط/);
  assert.match(el('#ic-cognia').innerHTML,/cognia:1:11:12:13/);
  assert.match(el('#ic-cognia').innerHTML,/nginx/);
  assert.doesNotMatch(el('#ic-cognia').innerHTML,/تجربه مشابه پیدا کرده/);"""
    )


def test_matching_cognia_document_shows_cited_source_and_prior_incident():
    import shutil
    import pytest
    if not shutil.which("node"):
        pytest.skip("Node unavailable")
    _render_cognia({
        "status": "available", "accepted_count": 1,
        "items": [{
            "title": "Verified incident recovery: gfpapi",
            "document_kind": "historical_incident_experience",
            "source_id": "cognia:1:116:127:2500", "knowledge_base_id": 1,
            "knowledge_id": 116, "revision_id": 127, "chunk_id": 2500,
            "document_service": "gfpapi", "previous_incident_id": "incident-previous-1",
            "symptom_pattern": ".NET startup timeout", "root_cause_status": "unconfirmed",
            "historical_action": "start_service", "verification_status": "success",
            "historical_outcome": "recovered", "reusable_lesson": "inspect appsettings",
            "relevance": 0.41, "use_status": "cited_by_agent",
            "excerpt": "Type: Verified Incident Experience\nService: gfpapi",
        }],
    }, """  const rendered=el('#ic-cognia').innerHTML;
  for(const term of ['incident-previous-1','.NET startup timeout','unconfirmed',
      'recovered','cognia:1:116:127:2500','Knowledge 116',
      'امتیاز تطبیق جست‌وجو','اثر بر تصمیم نهایی: تأییدنشده'])
    assert.match(rendered,new RegExp(term));
  assert.match(el('#ic-cognia-count').textContent,/۱ مرتبط/);""")
