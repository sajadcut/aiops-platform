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
    assert "const result=await api('/api/v1/approvals/'+encodeURIComponent(id)+'/'+suffix,options);" in js
    assert "if(button)void handleRecoveryApproval(button.dataset.recoveryApproval);" in js
    assert "if(action==='execute')await recheckServiceStatus();" in js


def test_approval_can_explicitly_include_execution_without_unrelated_storage_precheck():
    js = _room()
    assert "data-recovery-approval=\\"approve-execute\\"" in js
    assert "const combined=action==='approve-execute';" in js
    assert "const authorized=await api(url+'/approve',{method:'POST'});" in js
    assert "if(low(authorized.status)!=='approved')" in js
    assert "const result=await api(url+'/execute',{method:'POST'});" in js
    assert "if(attempted)await recheckServiceStatus();" in js
    assert "به‌تنهایی مانع Start مجاز سرویس نیست" in js
