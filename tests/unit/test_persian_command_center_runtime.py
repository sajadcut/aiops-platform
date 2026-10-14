"""Node-based regression for the real Command Center Persian runtime labels."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required")
def test_command_center_live_rendering_is_persian_and_preserves_operational_values():
    script = r"""
const assert=require('node:assert/strict');
const fs=require('fs'),vm=require('vm');
const source=fs.readFileSync('dashboards/control-center.js','utf8');
const html=fs.readFileSync('dashboards/index.html','utf8');
assert.match(html,/<html lang="fa" dir="rtl">/);
assert.match(html,/موارد نیازمند اقدام اپراتور/);
const elements=new Map();
const make=()=>({
  textContent:'',innerHTML:'',value:'',
  classList:{toggle(){},add(){},remove(){}},
  setAttribute(){},addEventListener(){},
});
const get=selector=>{
  if(!elements.has(selector))elements.set(selector,make());
  return elements.get(selector);
};
const ctx={
  console,Math,JSON,Number,String,Date,Intl,
  localStorage:{getItem:()=>null,setItem(){}},
  document:{
    querySelector:get,
    querySelectorAll:()=>[],
    addEventListener(){},
    hidden:false,
  },
  window:{addEventListener(){},location:{search:''}},
  setTimeout:()=>{},setInterval:()=>{},
};
vm.runInNewContext(source,ctx,{filename:'control-center.js'});
vm.runInNewContext([
 'S.summary={data_status:"live",incidents_active:1,incidents_critical:1,',
 ' approvals_pending:1,approvals_approved:0,execution_success:0,',
 ' successful_remediations:0,verification_partial:0,verification_inconclusive:0,',
 ' memory_entries_total:0,automation_success_rate:0,mean_confidence:0.4,',
 ' recent_audit:[{event_type:"approval_requested",created_at:"2026-10-14T12:00:00Z",',
 ' action:"start_service",status:"pending",incident_id:"123456789"}]};',
 'S.incidents=[{id:"inc1",service:"gfpapi",status:"open",severity:"critical",',
 ' summary:"systemd failed",approval_status:"pending",created_at:"2026-10-14T12:00:00Z"}];',
 'S.services=[{service:"gfpapi",latest_summary:"بررسی متوقف بودن سرویس",',
 ' incidents_active:1,critical_active:1,failed_executions:0,failed_verifications:0}];',
 'S.health={status:"ok",version:"2.3",components:{database:{status:"healthy"},',
 ' external:{zabbix_mcp:{healthy:false},prometheus_mcp:{healthy:true},',
 ' elasticsearch_mcp:{healthy:true}}}};',
 'renderOverview();renderHealth();',
].join('\n'),ctx);
assert.equal(get('#platformState').textContent,'فعال');
assert.match(get('#attentionBadge').textContent,/مورد فعال/);
assert.match(get('#attentionQueue').innerHTML,/شدت بحرانی/);
assert.match(get('#attentionQueue').innerHTML,/در انتظار تأیید/);
assert.match(get('#servicePreview').innerHTML,/بحرانی/);
assert.match(get('#automationLifecycle').innerHTML,/راستی‌آزمایی موفق/);
assert.match(get('#severityBreakdown').innerHTML,/بحرانی/);
assert.match(get('#auditPreview').innerHTML,/درخواست تأیید/);
assert.match(get('#components').innerHTML,/شواهد سامانه پایش/);
assert.match(get('#components').innerHTML,/در دسترس نیست/);
assert.equal(vm.runInNewContext('faStatus("failed")',ctx),'ناموفق');
assert.equal(vm.runInNewContext('faStatus("critical")',ctx),'بحرانی');
assert.equal(vm.runInNewContext('serviceState(S.services[0])',ctx),'critical');
assert.equal(vm.runInNewContext('attentionRank(S.incidents[0])',ctx),130);
"""
    result = subprocess.run(
        ["node", "-e", script],
        cwd=ROOT, text=True, capture_output=True, timeout=25,
    )
    assert result.returncode == 0, result.stderr
