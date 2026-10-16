"""Explicit .NET JSONC -> strict validated repair -> human approval contract."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from integrations.vm.dotnet_json_repair import dotnet_json_repair, dotnet_json_candidate
from integrations.vm.general_config_review import local_config_review
from integrations.vm.governed_config_change import rebuild_json_candidate
from apps.api.config_change_review import ConfigReviewResponse, _matching_proposal


PATH = '/data/gfp/gfpapi/appsettings.json'


def _broken():
    # A valid .NET comment and trailing comma appear BEFORE the real error.
    # Strict json.loads reports the comment, but the authoritative .NET
    # validator reports the later malformed key and object.
    return '''{
  // retained comment, accepted by .NET
  "logging": {"level": "Info",},
  "token": "SECRET_DO_NOT_LOG",
  "other": {
    brokenKey: true
  }
}
'''


def test_valid_dotnet_jsonc_needs_no_change():
    source = '{"key": 1, /* allowed */ "value": "secure",}\n'
    assert dotnet_json_candidate(source) is None
    inspected = local_config_review(base64.b64encode(source.encode()).decode(),
                                    path=PATH, syntax_profile='dotnet_jsonc')
    assert inspected['validation_status'] == 'FORMAT_VALID'
    assert inspected['status'] != 'candidate_proposed'


def test_dotnet_normalization_uses_true_error_line_and_keeps_value():
    src = _broken()
    found = dotnet_json_repair(src)
    assert found is not None
    updated, edits = found
    assert json.loads(updated)['token'] == 'SECRET_DO_NOT_LOG'
    assert json.loads(updated)['other']['brokenKey'] is True
    assert 'SECRET_DO_NOT_LOG' not in str(edits)
    assert '// retained comment' not in updated
    assert edits[0]['before'] == 'dotnet_jsonc_comments_or_trailing_commas'

    preview = local_config_review(base64.b64encode(src.encode()).decode(),
                                  path=PATH, syntax_profile='dotnet_jsonc')
    assert preview['status'] == 'candidate_proposed'
    assert preview['proposed_change'] == 'repair_dotnet_json_syntax'
    assert preview['candidate_hash'] == hashlib.sha256(updated.encode()).hexdigest()
    assert preview['source_hash'] == hashlib.sha256(src.encode()).hexdigest()
    assert preview['observed_error_line'] == 6
    assert 'SECRET_DO_NOT_LOG' not in str(preview)
    assert preview['execution_authority'] is False
    assert preview['apply_eligible'] is False
    assert preview['validation_status'] == 'FORMAT_CANDIDATE_VALID_ONLY'

    restored = rebuild_json_candidate(
        encoded=base64.b64encode(src.encode()).decode(), path=PATH,
        original_sha256=preview['source_hash'],
        candidate_sha256=preview['candidate_hash'],
        proposed_change=preview['proposed_change'],
    )
    assert restored == updated
    with pytest.raises(ValueError, match='config_source_hash_drift'):
        rebuild_json_candidate(
            encoded=base64.b64encode((src+' ').encode()).decode(), path=PATH,
            original_sha256=preview['source_hash'],
            candidate_sha256=preview['candidate_hash'],
            proposed_change=preview['proposed_change'],
        )

    proposal = {
        'status': 'candidate_proposed', 'service': 'gfpapi',
        'config_file': PATH, 'source_evidence_refs': ['vm:fresh:verified'],
        'original_sha256': preview['source_hash'],
        'candidate_sha256': preview['candidate_hash'],
        'proposed_change': preview['proposed_change'],
        'execution_authority': False, 'apply_eligible': False,
    }
    request = ConfigReviewResponse(
        decision='request_isolated_validation',
        expected_original_sha256=preview['source_hash'],
        expected_candidate_sha256=preview['candidate_hash'],
    )
    assert _matching_proposal(proposal, request) is True


def test_reject_duplicate_keys_and_values_not_a_valid_parser_fix():
    assert dotnet_json_candidate('{"a": 1, "a": 2}') is None
    assert dotnet_json_candidate('{"secrets":"valid", "foo": true}') is None


def test_strict_json_also_supported_without_dotnet_profile():
    bad = '{"root": {"child": true,}}'
    preview = local_config_review(base64.b64encode(bad.encode()).decode(),
                                  path=PATH, syntax_profile='strict_json')
    assert preview['status'] in {'file_observed', 'candidate_proposed', 'syntax_invalid_no_safe_candidate'}


@pytest.mark.asyncio
async def test_connector_and_orchestrator_preserve_candidate_to_preapproval(monkeypatch):
    from integrations.vm.ssh_connector import SSHVMConnector
    from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
    from apps.config_change_auto_queue import auto_queue_candidate

    connector = object.__new__(SSHVMConnector)
    monkeypatch.setattr(connector, '_validate_service', lambda _service: None)

    async def fake_validator(_target, _service):
        return {'success': True, 'supported': False, 'config_file': None}

    async def fake_discovery(_target, _service):
        return {'success': True, 'runtime': 'dotnet', 'files': [
            {'path': PATH, 'verified_exists': True},
        ]}

    async def fake_run(_target, _command):
        return {'success': True, 'stdout': base64.b64encode(_broken().encode()).decode()}

    monkeypatch.setattr(connector, 'config_validate', fake_validator)
    monkeypatch.setattr(connector, 'service_config_discovery', fake_discovery)
    monkeypatch.setattr(connector, '_run', fake_run)

    inspected = await connector.service_config_review('10.248.16.82', 'gfpapi')
    assert inspected['config_file'] == PATH
    assert inspected['status'] == 'candidate_proposed'
    assert inspected['proposed_change'] == 'repair_dotnet_json_syntax'

    state = {'service_name': 'gfpapi', 'context': {'evidence': [{
        'source': 'vm_mcp', 'reference': 'vm:config:live:1',
        'raw_data': {'diagnostic': 'service_config_review', **inspected},
    }]}}
    result = await DynamicInvestigationPlanner.propose(state, adapter=None)
    proposal = result['config_proposal']
    assert proposal['status'] == 'candidate_proposed'
    assert proposal['proposed_change'] == 'repair_dotnet_json_syntax'
    state['context']['dynamic_investigation'] = result
    queued = auto_queue_candidate(state)
    assert queued is not None
    assert queued['original_sha256'] == inspected['source_hash']
    assert queued['candidate_sha256'] == inspected['candidate_hash']
    assert queued['execution_authority'] is False