"""Manual incident dismissal is a persistent browser view, never deletion."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]

@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js required")
def test_hide_restore_survives_reload_and_poll_and_is_safe_in_all_view_sizes():
    code = r"""
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const html = fs.readFileSync('dashboards/index.html', 'utf8');
const script = html.slice(html.lastIndexOf('<script>') + 8, html.lastIndexOf('</script>'));
const css = fs.readFileSync('dashboards/control-center.css', 'utf8');
const ids = {
  first: '11111111-1111-4111-8111-111111111111',
  second: '22222222-2222-4222-8222-222222222222',
  archived: '33333333-3333-4333-8333-333333333333'
};
const storage = {};
const baseIncidents = [
  {id:ids.first, service:'gfpapi', status:'open', severity:'high', summary:'first', created_at:'2026-10-16T17:00:00Z'},
  {id:ids.second, service:'nginx', status:'open', severity:'low', summary:'second', created_at:'2026-10-16T16:00:00Z'},
];
const baseArchived = [
  {id:ids.archived, service:'tomcat', status:'closed', severity:'low', summary:'old', created_at:'2026-10-12T17:00:00Z'}
];
function initialize() {
  const elements = {
    incidentSearch:{value:''},severityFilter:{value:''},statusFilter:{value:''},
    incidentRows:{
      innerHTML:'', dataset:{}, listeners:{},
      addEventListener(type,handler){this.listeners[type]=handler;},
      contains(node){return node.inside===true;},
    },
    incidentCount:{textContent:''},
    incidentSort:{value:''},
    incidentHiddenToggle:{textContent:'',attrs:{},setAttribute(k,v){this.attrs[k]=v;}},
    incidentRestoreAll:{hidden:true},
  };
  const buttons = ['large','medium','small','list'].map(incidentSize => ({
    dataset:{incidentSize},setAttribute(){},
  }));
  const ctx = {
    S:{
      incidents:baseIncidents.map(i=>({...i})),
      archivedIncidents:baseArchived.map(i=>({...i})),
      incidentPeriod:'recent',archiveLoaded:true,
    },
    document:{querySelectorAll:selector => selector==='[data-incident-size]' ? buttons : []}, window:null,
    localStorage:{
      getItem:k=>Object.prototype.hasOwnProperty.call(storage,k)?storage[k]:null,
      setItem:(k,v)=>{storage[k]=v;},
    },
    $: selector => elements[selector.replace(/^#/, '')]||null,
    lower:v=>String(v||'').toLowerCase(),
    esc:v=>String(v||'').replaceAll('&','&amp;').replaceAll('<','&lt;'),
    isOpen:i=>!['resolved','closed'].includes(i.status),
    attentionReason:()=>[],attentionRank:()=>0,
    renderOverview:()=>{},renderIncidents:()=>{},toast:()=>{},
    Intl,Date,Math,console,Set,JSON,encodeURIComponent
  };
  ctx.window=ctx;
  vm.runInNewContext(script,ctx,{filename:'incident-dashboard.js'});
  const keys=()=>[...elements.incidentRows.innerHTML.matchAll(/href="\/dashboard\/incidents\/([^"]+)"/g)].map(m=>m[1]);
  return {ctx,elements,keys};
}
let {ctx,elements,keys}=initialize();
ctx.setIncidentDisplayMode('medium');
assert.deepEqual(keys(),[ids.first,ids.second]);
for (const mode of ['large','medium','small','list']) {
  ctx.setIncidentDisplayMode(mode);
  assert.match(elements.incidentRows.innerHTML,/data-incident-operation="hide"/);
  assert.match(elements.incidentRows.innerHTML,/class="incident-dismiss-btn"/);
  assert.match(elements.incidentRows.innerHTML,/پنهان کردن رخداد/);
}
// Ensure click is handled as a separate button, not the card anchor.
let stopped=false,prevented=false;
elements.incidentRows.listeners.click({
  target:{closest:()=>({
    inside:true,
    getAttribute:key => key==='data-incident-dismiss'?ids.first:'hide'
  })},
  preventDefault:()=>prevented=true,
  stopPropagation:()=>stopped=true,
});
assert.ok(stopped && prevented);
assert.deepEqual(keys(),[ids.second]);
assert.equal(ctx.isIncidentDismissed(ids.first),true);
assert.match(storage['aiops.incidents.hidden.v1'],/11111111-1111/);
ctx.S.incidents = baseIncidents.map(i=>({...i})); // Simulate a 6-second auto-fetch.
ctx.renderIncidents();
assert.deepEqual(keys(),[ids.second]);
// A refreshed browser page reloads the same persisted user preference.
({ctx,elements,keys}=initialize());
ctx.setIncidentDisplayMode('list');
assert.deepEqual(keys(),[ids.second]);
ctx.toggleHiddenIncidents();
assert.deepEqual(keys(),[ids.first]);
assert.equal(elements.incidentHiddenToggle.attrs['aria-pressed'],'true');
assert.equal(elements.incidentRestoreAll.hidden,false);
assert.match(elements.incidentRows.innerHTML,/data-incident-operation="restore"/);
ctx.restoreHiddenIncident(ids.first);
assert.deepEqual(keys(),[]);
ctx.toggleHiddenIncidents();
assert.deepEqual(keys(),[ids.first,ids.second]);
// Archive uses the same preference, without changing stored incidents.
ctx.S.incidentPeriod='archived';
ctx.renderIncidents();
assert.deepEqual(keys(),[ids.archived]);
assert.equal(ctx.hideIncidentFromDashboard(ids.archived),true);
assert.deepEqual(keys(),[]);
ctx.toggleHiddenIncidents();
assert.deepEqual(keys(),[ids.archived]);
ctx.restoreAllHiddenIncidents();
assert.deepEqual(keys(),[ids.archived]);
assert.equal(ctx.isIncidentDismissed(ids.archived),false);
assert.equal(JSON.parse(storage['aiops.incidents.hidden.v1']).length,0);
// Never conflate a presentation preference with DB deletions or status changes.
assert.doesNotMatch(script, /fetch\s*\([^)]*method:\s*['"]DELETE/);
assert.match(html,/id="incidentHiddenToggle"/);
assert.match(html,/id="incidentRestoreAll"/);
assert.match(css,/\.incident-dismiss-btn/);
console.log('incident dismissal, polling, refresh, archive, restore and accessibility passed');
"""
    result = subprocess.run(
        ["node", "-e", code], cwd=ROOT, capture_output=True,
        text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_attention_queue_filters_only_visual_items_not_immutable_backend_kpis():
    js = (ROOT / "dashboards/control-center.js").read_text(encoding="utf-8")
    assert "visibleOnThisDashboard(i)" in js
    assert "typeof window.isIncidentDismissed === 'function'" in js
    assert "x.incidents_active" in js
    assert "S.incidents.filter(i => visibleOnThisDashboard(i) && isOpen(i))" in js


def test_dismiss_button_is_not_a_new_list_row_and_uses_both_theme_palettes():
    """Regression for the screenshot showing a native × *under* each row."""
    root = ROOT
    html = (root / "dashboards/index.html").read_text(encoding="utf-8")
    css = (root / "dashboards/control-center.css").read_text(encoding="utf-8")
    list_markup = html.split("if (incidentSize === 'list') {", 1)[1].split(
        "$('#incidentRows').innerHTML = rows.map(i => {", 1
    )[0]
    # Separate sibling controls: the grid holds both. Never nest the button
    # inside the link, never put it after the row's closing wrapper.
    assert '${dismissal(i)}<a class="incident-list-row' in list_markup
    assert '</a></div>' in list_markup
    assert '</a>${dismissal(i)}</div>' not in list_markup
    assert 'incident-list-header-main' in list_markup
    assert 'incident-list-action-heading' in list_markup
    assert 'const icon = restoring ?' in html
    assert '<svg aria-hidden="true"' in html
    assert 'appearance:none;' in css
    assert 'position:static;' in css  # inline list actions; floating for cards
    assert 'grid-template-columns:50px minmax(0,1fr);' in css
    assert 'grid-column:1;' in css
    assert 'grid-column:2;' in css
    assert 'inset-inline-start:13px;' in css  # honors RTL icon placement
    assert 'color:var(--muted)' in css
    assert 'background:var(--red-soft)' in css
    assert 'color:var(--blue)' in css  # restore hover and accessible focus
    assert 'prefers-reduced-motion:reduce' in css
    # The previous screenshot strongly suggested stale HTML-vs-CSS bundles.
    assert '/dashboard/control-center.css?v=20261016-dismiss-ux2' in html
    assert '/dashboard/control-center.js?v=20261016-agent-durable1' in html
