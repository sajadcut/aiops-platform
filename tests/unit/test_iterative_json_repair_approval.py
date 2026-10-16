import asyncio
import json
from types import SimpleNamespace
from integrations.vm.iterative_json_repair import apply_edit_plan, build_json_candidate

class PlannedModel:
    def __init__(self, target):
        self.target = target
        self.rounds = 0
    async def generate(self, prompt, **kwargs):
        source = json.loads(prompt)['complete_config']
        assert kwargs['temperature'] == 0
        assert 'complete_config' in json.loads(prompt)
        self.rounds += 1
        # Test model proposes only one exact syntax correction each round.
        e = json.JSONDecoder()
        try: json.loads(source)
        except json.JSONDecodeError as ex: pass
        else: raise AssertionError('should only ask on invalid source')
        before = source.splitlines(keepends=True)
        if 'wrong:' in source:
            p = source.index('wrong:')
            a = [('"',p),('"',p+5)]
        elif 'other:' in source:
            p = source.index('other:')
            a = [('"',p),('"',p+5)]
        elif '{,' in source:
            p = source.index('{,')+1
            a = [('', p)]
            return SimpleNamespace(content=json.dumps({'edits':[{
                'line':source[:p].count('\n')+1,
                'column':p-source.rfind('\n',0,p), 'old':',','new':''
            }]}), finish_reason='stop')
        else: raise AssertionError(f'unplanned error in: {source!r}')
        edits=[]
        for ch,p in a:
            edits.append({'line':source[:p].count('\n')+1,
                          'column':p-source.rfind('\n',0,p), 'old':'','new':ch})
        return SimpleNamespace(content=json.dumps({'edits':edits}),finish_reason='stop')

def test_model_repairs_mixed_syntax_errors_and_keeps_secrets():
    broken = '{\n  wrong: 1,\n  other: "s3cr3t",\n  "nested": {,"ok":true}\n}\n'
    model = PlannedModel(None)
    result=asyncio.run(build_json_candidate(broken,model=model))
    assert result['status']=='candidate_proposed',result
    assert json.loads(result['candidate']) == {'wrong':1,'other':'s3cr3t','nested':{'ok': True}}
    assert result['grammar_edit_count'] == 5
    assert model.rounds == 3
    assert 's3cr3t' in result['candidate']

def test_value_edit_is_rejected():
    src='{"secret":"TOPSECRET", wrong: 1}'
    p=src.index('TOPSECRET')
    forged=json.dumps({'edits':[{'line':1,'column':p+1,'old':'T','new':'X'}]})
    assert apply_edit_plan(src, forged, failure_line=1) is None

def test_string_punctuation_edit_is_rejected():
    src='{"secret":"ABC:D", wrong: 1}'
    p=src.index(':D')
    forged=json.dumps({'edits':[{'line':1,'column':p+1,'old':':','new':''}]})
    assert apply_edit_plan(src, forged, failure_line=1) is None

def test_model_cannot_edit_other_lines():
    src='{\n  wrong: 1\n}\n' + ('\n'*12)
    edit=json.dumps({'edits':[{'line':15,'column':1,'old':'','new':','}]})
    assert apply_edit_plan(src, edit, failure_line=2) is None

def test_no_approval_for_unfixed_input():
    class BadModel:
        async def generate(self, prompt, **kwargs):
            return SimpleNamespace(content='explanation only',finish_reason='stop')
    result=asyncio.run(build_json_candidate('{wrong:1}',model=BadModel()))
    assert result['status']=='no_candidate'
    assert result['candidate'] is None
    assert result['reason']=='invalid_model_edit_plan'

def test_no_repair_to_valid_input():
    class DoNotCall:
        async def generate(self,*args,**kw): raise AssertionError()
    assert asyncio.run(build_json_candidate('{"x":1}',model=DoNotCall()))['reason']=='source_already_valid'

def test_large_complete_dotnet_file_multi_fault_repair_no_values_changed():
    original=json.dumps({f'key{i:03d}': {'enabled':True,'secret':f'secret-{i:03d}' }
                         for i in range(400)}, indent=2)+'\n'
    assert len(original)>16000
    broken=original.replace('"key036": {','key036: {',1)
    broken=broken.replace('"key038": {','key038: {',1)
    broken=broken.replace('"enabled": true', '"enabled": true,', 1)
    class FakeGrammarModel:
        calls=0
        async def generate(self,prompt,**kw):
            self.calls+=1
            text=json.loads(prompt)['complete_config']
            if 'true,,' in text:
                at=text.index('true,,')+5
                changes=[{'line':text[:at].count('\n')+1,
                          'column':at-text.rfind('\n',0,at),
                          'old':',','new':''}]
            elif 'key036:' in text or 'key038:' in text:
                key='key036:' if 'key036:' in text else 'key038:'
                at=text.index(key)
                changes=[{'line':text[:at].count('\n')+1,
                          'column':at-text.rfind('\n',0,at),
                          'old':'','new':'"'},
                         {'line':text[:at+len(key)-1].count('\n')+1,
                          'column':at+len(key)-1-text.rfind('\n',0,at+len(key)-1),
                          'old':'','new':'"'}]
            else: raise AssertionError('unknown fault')
            return SimpleNamespace(content=json.dumps({'edits':changes}),
                                   finish_reason='stop')
    # This test intentionally supplies the *entire* ~20KB file on each call.
    # The malformed "true,," is in the first object and the bare keys later.
    agent=FakeGrammarModel()
    result=asyncio.run(build_json_candidate(broken,model=agent))
    assert result['status']=='candidate_proposed',result
    assert json.loads(result['candidate'])==json.loads(original)
    assert result['original_sha256']!=result['candidate_sha256']
    assert agent.calls>=3


def test_independent_guard_accepts_only_exact_original_key_and_grammar_bytes():
    from integrations.vm.iterative_json_repair import independently_verify_structural_candidate as verify
    before='{"password":"TOP{SECRET}", wrong:1, other: {,"enabled": true}}'
    after='{"password":"TOP{SECRET}", "wrong":1, "other": {"enabled": true}}'
    assert json.loads(after)
    assert verify(before,after)
    assert not verify(before,after.replace('TOP{SECRET}','TOP{SECRET}!'))
    assert not verify(before,after.replace('"enabled": true','"enabled": "true"'))
    assert not verify(before,after.replace('"wrong"','"WRONG"'))
    assert not verify(after,after)
    assert not verify(before,after,maximum_edits=2)


def test_independent_guard_handles_large_file_with_multiple_bare_keys():
    from integrations.vm.iterative_json_repair import independently_verify_structural_candidate as verify
    correct=json.dumps({f'key{i:03d}': {'enabled':True, 'secret':f'SECRET{i:03d}'}
                        for i in range(400)},indent=2)
    corrupt=correct.replace('"key036":','key036:',1).replace('"key038":','key038:',1)
    assert verify(corrupt,correct)
    assert not verify(corrupt,correct.replace('SECRET039','SECRET040'))
