"""Regression: a distinct approved service Start must not be sent to E2E resume.

Production symptom: /approvals/<recovery-id>/approve returned 200, but a
separate /workflow/e2e/<incident-id>/resume returned 409 approval_not_granted.
"""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
JS = ROOT / "dashboards" / "incident-command-room.js"


def test_recovery_approval_does_not_lose_action_controls_to_workflow_approval():
    src = JS.read_text(encoding="utf-8")
    assert "const separateWorkflow=UUID.test(String(durable.approval_id||''))" in src
    assert "Two different approvals exist:" in src
    assert "['pending','approved','consumed'].includes(recoveryStatus)" in src
    assert "data-recovery-approval=\"execute\"" in src
    assert "const independentRecovery=kind==='resume'&&" in src
    assert "await handleRecoveryApproval('execute');" in src
    assert "if(independentRecovery){" in src
    assert "await api('/api/v1/workflow/e2e/'+encodeURIComponent(incidentId)+'/resume'" in src


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js not installed")
def test_browser_decision_renders_approved_start_with_separate_paused_workflow():
    harness = r"""
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const src=fs.readFileSync('dashboards/incident-command-room.js','utf8');
function section(first,last){
  const a=src.indexOf(first),b=src.indexOf(last,a);
  assert(a>=0&&b>a,'extract '+first);
  return src.slice(a,b);
}
const decision=section('  function renderDecision(r) {','  function render() {');
for(const mainStatus of ['pending','approved','pending_validation']){
  const views={};
  const recovery='605493f9-6903-4c77-a78f-cf116615330e';
  const state={
    historic:false,language:'fa',busy:false,
    lifecycle:{checkpoint_status:'paused',approval:{
      approval_id:'f0f0f0f0-0000-4000-8000-000000000001',
      status:mainStatus, metadata:{binding_complete:true}}},
    recoveryApproval:{approval_id:recovery,status:'approved',
      action:'start_service',target:'10.248.16.82',service:'nginx'},
    report:{incident_summary:{service:'nginx'}}
  };
  const env={
    state,
    UUID:/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i,
    low:v=>String(v||'').toLowerCase(), esc:v=>String(v??''),
    txt:v=>String(v??''),pill:v=>String(v??''),mini:(k,v)=>k+':'+v,
    tr:k=>k, humanAction:x=>String(x||''),humanTool:x=>String(x||''),
    status:x=>String(x||''),show:(id,html)=>views[id]=html,
  };
  vm.runInNewContext(decision+';globalThis.run=renderDecision;',env);
  env.run({approval_readiness:{},remediation_recommendation:{}});
  assert(views['#ic-action-controls'].includes('data-recovery-approval="execute"'),
         mainStatus+' hides approved recovery Start');
  assert(!views['#ic-action-controls'].includes('id="ic-resume"'),
         'E2E resume must not masquerade as service start');
  assert(views['#ic-action-controls'].includes('دو مجوز متفاوت'),
         'Mismatch needs a clear operator-facing explanation');
  assert(views['#ic-action-state'].includes(recovery),
         'Operator should see exact service recovery approval ID');
}
const action=section('  async function action(kind) {','  function bind(){');
(async()=>{
  let delegated=[],writes=[];
  const env={
    state:{
      busy:false,historic:false,report:{snapshot_id:'brief'},
      lifecycle:{checkpoint_status:'paused',approval:{
        approval_id:'f0f0f0f0-0000-4000-8000-000000000001',status:'approved'}},
      recoveryApproval:{approval_id:'605493f9-6903-4c77-a78f-cf116615330e',
        status:'approved',action:'start_service',service:'nginx',target:'10.248.16.82'},
    },
    low:v=>String(v||'').toLowerCase(),
    UUID:/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i,
    handleRecoveryApproval:async mode=>delegated.push(mode),
    api:async url=>{writes.push(url);throw Error('no accidental e2e call')},
  };
  vm.runInNewContext(action+';globalThis.run=action;',env);
  await env.run('resume');
  assert.deepEqual(delegated,['execute']);
  assert.deepEqual(writes,[]);
  // No authorization boundary permits graph resume merely because the
  // displayed workflow approval ID happens to equal the recovery ticket.
  env.state.lifecycle.approval.approval_id=env.state.recoveryApproval.approval_id;
  await env.run('resume');
  assert.deepEqual(delegated,['execute','execute']);
  assert.deepEqual(writes,[]);
})().catch(e=>{console.error(e);process.exitCode=1});
"""
    result = subprocess.run(
        ["node", "-e", harness], cwd=ROOT,
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr[-3500:]
