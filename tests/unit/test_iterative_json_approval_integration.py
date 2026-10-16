"""Requires installed aiops-platform source checkout; not a live VM test.

Checks LLM-output rejection -> multi-round correction -> encrypted-vault
contract -> DynamicInvestigation -> auto-approval *prevalidation intent*.
No production file is ever written or human approval forged.
"""
import base64
import json
from types import SimpleNamespace

import pytest
from apps.config_change_auto_queue import auto_queue_candidate
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from integrations.vm import full_config_llm_repair as repair


class FakeModel:
    def __init__(self):
        self.rounds = 0

    async def generate(self, prompt, **kwargs):
        if kwargs['stage'] == 'full_config_llm_repair':
            return SimpleNamespace(content='This is not an edit plan.', finish_reason='stop')
        assert kwargs['stage'] == 'iterative_config_grammar_repair'
        self.rounds += 1
        text=json.loads(prompt)['complete_config']
        if 'wrong:' in text:
            at=text.index('wrong:')
            changes=[(at,'','"'), (at+5,'','"')]
        elif 'other:' in text:
            at=text.index('other:')
            changes=[(at,'','"'), (at+5,'','"')]
        elif '{,' in text:
            at=text.index('{,')+1
            changes=[(at,',','')]
        else:
            raise AssertionError('unexpected syntax fault')
        edits=[]
        for at, old, new in changes:
            edits.append({'line':text[:at].count('\n')+1,
                          'column':at-text.rfind('\n',0,at),
                          'old':old,'new':new})
        return SimpleNamespace(content=json.dumps({'edits':edits}),finish_reason='stop')


@pytest.mark.asyncio
async def test_explicit_full_config_llm_repair_produces_auto_prevalidation_intent(monkeypatch):
    broken='{\n  wrong: 1,\n  other: "supersecret",\n  "nested": {,"ok":true}\n}\n'
    corrected=json.loads('{"wrong":1,"other":"supersecret","nested":{"ok":true}}')
    fake=FakeModel()
    monkeypatch.setattr(repair.settings, 'AIOPS_FULL_CONFIG_LLM_ENABLED',True)
    monkeypatch.setattr(repair.settings, 'LLM_BASE_URL','https://trusted-model.test')
    sealed=[]
    def store(**kwargs):
        sealed.append(kwargs)
        return {'candidate_stored':True, 'candidate_ttl_seconds':900}
    monkeypatch.setattr(repair,'store_candidate',store)
    raw=await repair.review_complete_config(
        base64.b64encode(broken.encode()).decode(),
        service='gfpapi', path='/data/gfp/gfpapi/appsettings.json',
        target='10.248.16.82',model=fake)
    assert raw['status']=='llm_candidate_proposed',raw
    assert raw['candidate_stored'] is True
    assert raw['llm_returned_complete_file'] is True
    assert raw['validation_profile']=='json_syntax'
    assert json.loads(sealed[0]['candidate']) == corrected
    assert fake.rounds==3
    evidence=[{'source':'vm_mcp','reference':'vm:llm:verified', 'raw_data':{
        **raw,'success':True,'diagnostic':'service_config_llm_repair',
        'target':'10.248.16.82','service':'gfpapi',
    }}]
    state={'service_name':'gfpapi','context':{'evidence':evidence}}
    result=await DynamicInvestigationPlanner.propose(state,adapter=None)
    assert result['config_proposal']['status']=='candidate_proposed'
    assert result['config_proposal']['candidate_stored'] is True
    state['context']['dynamic_investigation']=result
    queued=auto_queue_candidate(state)
    assert queued is not None
    assert queued['proposed_change']=='llm_full_file_repair'
    assert queued['apply_eligible'] is False
    assert queued['execution_authority'] is False
