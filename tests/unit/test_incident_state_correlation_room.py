"""Real Incident Room JS render of Down versus Running; no synthetic tool calls."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required for actual dashboard JS")
def test_section01_displays_source_discrepancy_timing_and_safe_read_only_steps():
    existing=(ROOT/"tests/unit/test_technical_investigation_browser.py").read_text(encoding="utf-8")
    start=existing.index('    script = r"""')+len('    script = r"""')
    end=existing.index('"""',start)
    script=existing[start:end]
    correlation={
        "conclusion_kind":"source_discrepancy","headline_fa":
          "اختلاف وضعیت شناسایی شد: Zabbix برای gfpapi هشدار Down ثبت کرده، اما VM MCP وضعیت Running در systemd مشاهده کرده است.",
        "conclusion_fa":"گزارش Zabbix و VM MCP دربارهٔ وضعیت سرویس اختلاف دارند؛ بازیابی واقعی ثابت نشده است.",
        "alert":{"reported_down":True,"observed_at":None,"time_basis":"not_recorded",
                 "received_at":"2026-10-14T14:00:00Z","evidence_refs":["alert-01"]},
        "last_vm_observation":{"active_state":"active","sub_state":"running",
                 "observed_at":"2026-10-14T14:01:00Z","evidence_refs":["vm-01"]},
        "contradictions":[{"contradiction_type":"zabbix_down_vs_vm_systemd_running",
                           "temporal_relation":"undetermined"}],
        "http_observation":None,
        "next_steps_fa":["مقایسهٔ زمان دقیق Event و Item History زبیکس",
                         "بررسی MainPID، RestartCount و Journal سرویس",
                         "بررسی مستقل HTTP Health و TCP پس از ثبت Endpoint معتبر"],
        "unknowns_fa":["سلامت HTTP بررسی نشده است"],
        "confirmed_observations":[
            {"text_fa":"Zabbix Down گزارش کرده است.","evidence_refs":["alert-01"]},
            {"text_fa":"VM MCP Running مشاهده کرده است.","evidence_refs":["vm-01"]}],
        "cross_source_findings":[{
            "status":"scope_mismatch_not_a_contradiction",
            "statement_fa":"Elasticsearch برای سرویس نتیجهٔ صفر ثبت کرده، ولی Journal همین VM دو خطای مرتبط دارد؛ صفر نتیجهٔ Elastic سلامت OS نیست.",
            "query_scope":"service_only_or_host_filter_unverified",
            "evidence_refs":["elastic-observation-01","vm-journal-02"],
            "journal_signatures":{"error":2,"timeout":1},
            "cause_confirmed":False}],
        "hypotheses":[],"authorizes_execution":False
    }
    assert "  const report={" in script
    script=script.replace("  const report={","  const report={state_correlation:"+
                          json.dumps(correlation,ensure_ascii=False)+",",1)
    # The comparison must be in the primary section, not only hidden drilldowns.
    marker="  const page=el('#ic-technical-report').innerHTML;"
    assert marker in script
    script=script[:script.index(marker)]+r"""
  const card=el('#ic-operational-summary').innerHTML;
  const main=el('#ic-diagnosis').innerHTML;
  const lead=el('#ic-brief-lead').innerHTML;
  for(const phrase of ['Zabbix','VM MCP','Down','Running','اختلاف وضعیت',
                       'زمان دریافت هشدار جای زمان وقوع Event نیست',
                       'سه بررسی بعدی','Journal','HTTP Health']){
    assert.match(card,new RegExp(phrase));
  }
  assert.match(card,/alert-01/);
  assert.match(card,/vm-01/);
  assert.match(card,/Elasticsearch برای سرویس نتیجهٔ صفر/);
  assert.match(card,/Journal همین VM/);
  assert.match(card,/elastic-observation-01/);
  assert.match(card,/vm-journal-02/);
  assert.match(card,/service_only_or_host_filter_unverified/);
  assert.doesNotMatch(card,/خطایی در سیستم‌عامل وجود ندارد/);
  assert.match(main,/اختلاف وضعیت شناسایی شد/);
  assert.match(lead,/بازیابی واقعی ثابت نشده/);
  assert.doesNotMatch(card,/False Positive تأیید شد/);
  assert.equal(posted.length,0);
})();
"""
    run=subprocess.run([shutil.which("node"),"-e",script],cwd=ROOT,
                       capture_output=True,text=True,timeout=22)
    assert run.returncode==0,run.stderr


def test_correlation_card_is_defined_and_exposes_no_auto_execute_paths():
    script=(ROOT/"dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert "state_correlation" in script
    assert "zabbix_down_vs_vm_systemd_running" in script
    assert "function renderOperationalSummary(" in script
    assert "noProposedAction(report)" in script
    assert "state.serviceStatus.observed_at" in script
