"""Recovery approval must expose a real, explicit Start action in Incident Room.

The Decision Brief can carry a separate E2E pending approval while the actual
approved recovery ticket is ready. The top of the page must not hide it.
"""
from pathlib import Path


def _room():
    return (Path(__file__).resolve().parents[2] /
            "dashboards" / "incident-command-room.js").read_text(encoding="utf-8")


def test_approved_start_visible_in_hero_even_with_other_workflow_approval():
    js = _room()
    assert "const recoveryApproved=!state.historic&&" in js
    assert "state.recoveryApproval?.status==='approved'" in js
    assert "['start_service','restart_service'].includes(state.recoveryApproval?.action)" in js
    assert "recoveryApproved\n      ? '<small>'" in js
    assert "data-recovery-approval=\"execute\"" in js
    assert "renderHero(state.report);" in js


def test_start_is_not_mislabelled_restart_and_needs_explicit_execution():
    js = _room()
    assert "const verb=approval.action==='start_service'?'Start':'Restart';" in js
    assert "const recoveryIsStart=state.recoveryApproval?.action==='start_service';" in js
    assert "recovery.suggested_action==='start_service'?'Start':'Restart'" in js
    assert "if(action==='execute'&&approval.status!=='approved')return;" in js
    assert "const result=await api(url+'/'+action,options);" in js
    assert "if(button)void handleRecoveryApproval(button.dataset.recoveryApproval);" in js
    assert "if(attempted)await recheckServiceStatus();" in js


def test_approval_can_explicitly_include_execution_without_unrelated_storage_precheck():
    js = _room()
    assert 'data-recovery-approval="approve-execute"' in js
    assert "const combined=action==='approve-execute';" in js
    assert "const authorized=await api(url+'/approve',{method:'POST'});" in js
    assert "if(low(authorized.status)!=='approved')" in js
    assert "const result=await api(url+'/execute',{method:'POST'});" in js
    assert "if(attempted)await recheckServiceStatus();" in js
    assert "به‌تنهایی مانع Start مجاز سرویس نیست" in js


def test_node_runtime_approved_start_dispatches_two_governed_calls_in_order():
    import shutil
    import subprocess

    import pytest

    if not shutil.which("node"):
        pytest.skip("Node.js browser-regression harness unavailable")
    harness = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const src = fs.readFileSync('dashboards/incident-command-room.js','utf8');
const begin = src.indexOf('  async function handleRecoveryApproval(action) {');
const end = src.indexOf('  function dotnetSyntaxLabel(item,fa)', begin);
assert.ok(begin>0&&end>begin,'recovery handler exists');
const fn = src.slice(begin,end);
async function attempt(action, status, responseMode) {
  const calls = [], messages = [];
  let rechecks=0, reloads=0, confirmations=0;
  const state = { historic:false, busy:false, language:'fa',
    report:{}, loadingToken:3,
    recoveryApproval:{approval_id:'11111111-1111-4111-8111-111111111111',
      action:'start_service',service:'nginx',target:'10.248.16.82',status}
  };
  const env = {
    state, UUID:/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    low:v=>String(v||'').toLowerCase(),
    confirm:v=>{confirmations++;assert.ok(v.includes('Start'));return true;},
    prompt:()=>'', tr:v=>v,
    renderInvestigation:()=>{},renderHero:()=>{},
    notify:(text,failed)=>messages.push({text,failed}),
    api:async (url,opts)=>{
      assert.equal(opts.method,'POST');
      calls.push(url);
      if(url.endsWith('/approve'))
        return {status:responseMode==='approval_failed'?'pending':'approved'};
      if(url.endsWith('/execute')) {
        if(responseMode==='preflight_rejected')
          throw new Error('remediation_precondition_failed:service_configuration_invalid');
        return {success:true,status:'consumed'};
      }
      throw Error('Unexpected write '+url);
    },
    load:async()=>{reloads++;},
    recheckServiceStatus:async()=>{rechecks++;},
    loadRecoveryApproval:async()=>{},
  };
  vm.runInNewContext(fn+';globalThis.recoveryHandler=handleRecoveryApproval;',env);
  await env.recoveryHandler(action);
  return {calls,messages,rechecks,reloads,confirmations};
}
(async()=>{
  const root='/api/v1/approvals/11111111-1111-4111-8111-111111111111';
  const ok=await attempt('approve-execute','pending');
  assert.deepEqual(ok.calls,[root+'/approve',root+'/execute']);
  assert.equal(ok.rechecks,1);
  assert.equal(ok.reloads,1);
  assert.equal(ok.confirmations,1);
  const denied=await attempt('approve-execute','pending','approval_failed');
  assert.deepEqual(denied.calls,[root+'/approve']);
  assert.equal(denied.rechecks,0);
  const gate=await attempt('approve-execute','pending','preflight_rejected');
  assert.deepEqual(gate.calls,[root+'/approve',root+'/execute']);
  assert.equal(gate.rechecks,1);
  assert.ok(gate.messages.some(m=>m.failed));
  const existing=await attempt('execute','approved');
  assert.deepEqual(existing.calls,[root+'/execute']);
  assert.equal(existing.rechecks,1);
})().catch(e=>{console.error(e);process.exit(1)});
"""
    finished = subprocess.run(
        ["node", "-e", harness],
        cwd=__import__("pathlib").Path(__file__).resolve().parents[2],
        text=True, capture_output=True, timeout=12,
    )
    assert finished.returncode == 0, (finished.stderr or finished.stdout)[-3500:]
