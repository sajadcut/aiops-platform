"""Incident Explorer regression: date order, active/history scope and Windows-size views."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js required")
def test_incident_explorer_sort_filter_persistence_and_views():
    code = r"""
const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
const html=fs.readFileSync('dashboards/index.html','utf8');
const source=html.slice(html.lastIndexOf('<script>')+8,html.lastIndexOf('</script>'));
const storage={};
const elements={
  incidentSearch:{value:''},severityFilter:{value:''},statusFilter:{value:''},
  incidentCount:{textContent:''},incidentRows:{innerHTML:'',dataset:{}},
  incidentSort:{value:''}
};
const buttons=['large','medium','small','list'].map(size=>({
  dataset:{incidentSize:size},attrs:{},
  setAttribute(k,v){this.attrs[k]=v;}
}));
const ctx={
  S:{incidents:[
    {id:'old',service:'nginx',status:'open',severity:'high',approval_status:'pending',
     summary:'Old',created_at:'2026-01-01T10:00:00Z'},
    {id:'new',service:'api',status:'open',severity:'low',
     summary:'New',created_at:'2026-10-11T10:00:00Z'},
    {id:'unknown',service:'db',status:'open',severity:'medium',summary:'Unknown'},
    {id:'closed',service:'cache',status:'resolved',severity:'low',
     summary:'Closed',created_at:'2026-08-11T10:00:00Z'}
  ]},
  document:{querySelectorAll:()=>buttons},
  localStorage:{
    getItem:k=>storage[k]||null,
    setItem:(k,v)=>{storage[k]=v;}
  },
  window:null,
  $:id=>elements[id.replace(/^#/,'')]||null,
  lower:v=>String(v||'').toLowerCase(),
  esc:v=>String(v||'').replaceAll('&','&amp;').replaceAll('<','&lt;'),
  isOpen:i=>!['closed','resolved'].includes(i.status),
  attentionReason:()=>[], attentionRank:()=>0,
  renderOverview:()=>{},renderIncidents:()=>{},
  Intl,Date,Math,console,
};
ctx.window=ctx;
vm.runInNewContext(source,ctx,{filename:'incident-explorer-inline.js'});
const keys=()=>[...elements.incidentRows.innerHTML.matchAll(/href="\/dashboard\/incidents\/([^"]+)"/g)].map(m=>m[1]);
ctx.setIncidentSort('newest');
assert.deepEqual(keys(),['new','closed','old','unknown']);
ctx.setIncidentSort('oldest');
assert.deepEqual(keys(),['old','closed','new','unknown']);
ctx.setIncidentSort('priority');
assert.deepEqual(keys(),['old','new','closed','unknown']);
elements.statusFilter.value='__active__';
ctx.setIncidentSort('newest');
assert.deepEqual(keys(),['new','old','unknown']);
ctx.setIncidentDisplayMode('small');
assert.equal(elements.incidentRows.dataset.size,'small');
assert.equal(buttons[2].attrs['aria-pressed'],'true');
assert.equal(buttons[0].attrs['aria-pressed'],'false');
assert.equal(storage['aiops.incidents.size'],'small');
assert.equal(storage['aiops.incidents.sort'],'newest');
ctx.setIncidentDisplayMode('large');
assert.equal(elements.incidentRows.dataset.size,'large');
assert.equal(buttons[0].attrs['aria-pressed'],'true');
ctx.setIncidentDisplayMode('list');
assert.equal(elements.incidentRows.dataset.size,'list');
assert.equal(storage['aiops.incidents.size'],'list');
assert.equal(buttons[3].attrs['aria-pressed'],'true');
assert.equal(buttons[2].attrs['aria-pressed'],'false');
assert.match(elements.incidentRows.innerHTML,/class="incident-list-header"/);
assert.match(elements.incidentRows.innerHTML,/class="incident-list-row /);
assert.match(elements.incidentRows.innerHTML,/شرح کوتاه/);
assert.match(elements.incidentRows.innerHTML,/شروع رخداد/);
assert.match(elements.incidentRows.innerHTML,/وضعیت تأیید/);
assert.match(elements.incidentRows.innerHTML,/منتظر تأیید شما/);
assert.deepEqual(keys(),['new','old','unknown']);
elements.statusFilter.value='';
ctx.setIncidentSort('oldest');
assert.deepEqual(keys(),['old','closed','new','unknown']);
assert.match(elements.incidentRows.innerHTML,/رفع شده/);
ctx.setIncidentSort('newest');
elements.statusFilter.value='__active__';
ctx.setIncidentDisplayMode('list');
assert.deepEqual(keys(),['new','old','unknown']);
ctx.setIncidentDisplayMode('large');
ctx.setIncidentSort('not-a-sort');
assert.equal(storage['aiops.incidents.sort'],'newest');
ctx.setIncidentDisplayMode('invalid');
assert.equal(elements.incidentRows.dataset.size,'large');
assert.match(elements.incidentRows.innerHTML,/نیازمند تصمیم شما/);
assert.match(html,/data-incident-size="large"/);
assert.match(html,/data-incident-size="medium"/);
assert.match(html,/data-incident-size="small"/);
assert.match(html,/data-incident-size="list"/);
const css=fs.readFileSync('dashboards/control-center.css','utf8');
assert.match(css,/\.incident-cards\[data-size="list"\]/);
assert.match(css,/grid-template-columns:minmax\(165px/);
assert.match(html,/id="incidentSort"/);
console.log('Incident Explorer ordering and view sizes passed');
"""
    r = subprocess.run(
        ["node", "-e", code], cwd=ROOT, capture_output=True,
        text=True, timeout=20,
    )
    assert r.returncode == 0, r.stderr


def test_incident_brief_has_clear_headline_and_expandable_originals():
    js = (ROOT / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    html = (ROOT / "dashboards/incident-command-room.html").read_text(encoding="utf-8")
    assert "در ۳۰ ثانیه چه بدانم؟" not in js + html
    assert "خلاصه وضعیت و پیشنهاد AIOps" in html
    assert "function plainLead(r)" in js
    assert "signalFacts(raw)" in js
    assert "previousExperience(item, kind)" in js
    assert "const original =" in js
    assert '<details class="ic-technical ic-evidence-refs">' in js
    assert "humanAction" in js
    assert "start_service:'راه‌اندازی سرویس'" in js
    assert "execution_request_received" not in js  # no alternate execution contract
