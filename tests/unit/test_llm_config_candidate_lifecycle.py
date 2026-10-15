"""Safety regression coverage for encrypted complete-file LLM repair lifecycle.

No target VM is modified. A real VM mount namespace + sudo validation
remains an external acceptance gate; synthetic edge calls cannot prove that.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from integrations.vm.config_candidate_vault import (
    CandidateUnavailable, load_candidate, store_candidate,
)
from integrations.vm.full_config_llm_repair import review_complete_config
from integrations.vm.governed_config_change import run_governed_change

TARGET = "192.0.2.80"
SERVICE = "nginx"
PATH = "/etc/nginx/nginx.conf"
SOURCE = "events {}\nhttp {\n server {\n listen 8080; {\n }\n}\n"
CORRECTED = SOURCE.replace("listen 8080; {", "listen 8080;")
HASH_SOURCE = hashlib.sha256(SOURCE.encode()).hexdigest()
HASH_CORRECTED = hashlib.sha256(CORRECTED.encode()).hexdigest()


@pytest.fixture
def vault_env(tmp_path, monkeypatch):
    from integrations.vm import config_candidate_vault as vault
    key = base64.b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setattr(vault.settings, "AIOPS_CONFIG_CANDIDATE_ENCRYPTION_KEY", key)
    monkeypatch.setattr(vault.settings, "AIOPS_CONFIG_CANDIDATE_DIRECTORY", str(tmp_path / "private"))
    return tmp_path / "private"


def put(**overrides):
    fields = {"target": TARGET, "service": SERVICE, "path": PATH,
              "source_hash": HASH_SOURCE, "candidate_hash": HASH_CORRECTED,
              "candidate": CORRECTED}
    fields.update(overrides)
    return store_candidate(**fields)


def get(**overrides):
    fields = {"target": TARGET, "service": SERVICE, "path": PATH,
              "source_hash": HASH_SOURCE, "candidate_hash": HASH_CORRECTED}
    fields.update(overrides)
    return load_candidate(**fields)


def test_aes_gcm_persistent_storage_is_secret_safe_and_hash_bound(vault_env):
    result = put()
    assert result["candidate_stored"] is True
    assert result["candidate_ttl_seconds"] == 86400
    files = list(vault_env.iterdir())
    assert len(files) == 1
    assert CORRECTED.encode() not in files[0].read_bytes()
    assert SOURCE.encode() not in files[0].read_bytes()
    assert get() == CORRECTED
    assert not files[0].stat().st_mode & 0o077
    assert not vault_env.stat().st_mode & 0o077
    with pytest.raises(CandidateUnavailable):
        get(target="192.0.2.81")
    with pytest.raises(CandidateUnavailable):
        get(service="payments")
    with pytest.raises(CandidateUnavailable):
        get(source_hash="a" * 64)
    with pytest.raises(CandidateUnavailable):
        get(candidate_hash="b" * 64)


def test_wrong_key_tamper_and_expiry_fail_closed(vault_env, monkeypatch):
    from integrations.vm import config_candidate_vault as vault
    put()
    stored = next(vault_env.iterdir())
    sealed = stored.read_bytes()
    stored.write_bytes(sealed[:-1] + bytes([sealed[-1] ^ 1]))
    with pytest.raises(CandidateUnavailable, match="candidate_decryption_failed"):
        get()
    stored.write_bytes(sealed)
    monkeypatch.setattr(vault.time, "time", lambda: 1780000000 + 90000)
    # Stored timestamps are from actual current test run, so always move past
    # the stored timestamp rather than a particular wall clock date.
    created = int.from_bytes(sealed[4:12], "big")
    monkeypatch.setattr(vault.time, "time", lambda: created + 86400)
    with pytest.raises(CandidateUnavailable, match="candidate_expired"):
        get()
    monkeypatch.setattr(vault.time, "time", lambda: created + 1)
    monkeypatch.setattr(vault.settings, "AIOPS_CONFIG_CANDIDATE_ENCRYPTION_KEY",
                        base64.b64encode(os.urandom(32)).decode("ascii"))
    with pytest.raises(CandidateUnavailable, match="candidate_decryption_failed"):
        get()


def test_expired_same_candidate_can_be_renewed_safely(vault_env, monkeypatch):
    from integrations.vm import config_candidate_vault as vault
    assert put()["candidate_stored"] is True
    sealed_before = next(vault_env.glob("*.sealed")).read_bytes()
    created = int.from_bytes(sealed_before[4:12], "big")
    monkeypatch.setattr(vault.time, "time", lambda: created + 86401)
    with pytest.raises(CandidateUnavailable, match="candidate_expired"):
        get()
    assert put()["candidate_stored"] is True
    sealed_after = next(vault_env.glob("*.sealed")).read_bytes()
    assert sealed_before != sealed_after
    assert get() == CORRECTED


def test_vault_requires_strong_key_and_no_symlink(vault_env, monkeypatch):
    from integrations.vm import config_candidate_vault as vault
    monkeypatch.setattr(vault.settings, "AIOPS_CONFIG_CANDIDATE_ENCRYPTION_KEY", "")
    with pytest.raises(CandidateUnavailable, match="candidate_key_not_configured"):
        put()
    monkeypatch.setattr(vault.settings, "AIOPS_CONFIG_CANDIDATE_ENCRYPTION_KEY",
                        base64.b64encode(os.urandom(32)).decode("ascii"))
    vault_env.mkdir(exist_ok=True)
    alias = vault_env / "alias"
    alias.symlink_to(vault_env, target_is_directory=True)
    monkeypatch.setattr(vault.settings, "AIOPS_CONFIG_CANDIDATE_DIRECTORY", str(alias))
    with pytest.raises(CandidateUnavailable):
        put()


class Model:
    def __init__(self, content=CORRECTED):
        self.content = content
    async def generate(self, prompt, **kwargs):
        assert json.loads(prompt)["complete_config"] == SOURCE
        from types import SimpleNamespace
        return SimpleNamespace(content=json.dumps({"corrected_config": self.content}),
                               finish_reason="stop")


@pytest.mark.asyncio
async def test_full_source_is_sent_complete_and_correction_is_sealed(vault_env, monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://trusted-llm.example")
    result = await review_complete_config(
        base64.b64encode(SOURCE.encode()).decode(),
        target=TARGET, service=SERVICE, path=PATH,
        vendor_error='"listen" directive is not allowed here',
        model=Model(),
    )
    assert result["status"] == "llm_candidate_proposed"
    assert result["candidate_stored"] is True
    assert result["candidate_hash"] == HASH_CORRECTED
    assert result["source_hash"] == HASH_SOURCE
    assert result["changed_line_numbers"] == [4]
    assert result["validation_profile"] == "nginx"
    assert result["apply_eligible"] is False
    assert result["execution_authority"] is False
    assert result["validator_executed_on_proposal"] is False
    assert get() == CORRECTED
    assert "listen" not in str(result) and SOURCE not in str(result)


def test_llm_cannot_hide_modified_ports_hosts_or_directives_behind_redacted_diff():
    from integrations.vm.full_config_llm_repair import _candidate_preview
    for changed in (
        SOURCE.replace("8080", "8081"),
        SOURCE.replace("listen", "deny"),
        SOURCE.replace("events", "http"),
    ):
        result = _candidate_preview(SOURCE, changed)
        assert result["status"] == "llm_candidate_rejected"
        assert result["rejection_reason"] == "candidate_changes_configuration_values"
        assert result["candidate_hash"] is None
    source = '{"url":"https://example.com/a,b","enabled":true,}\n'
    malicious = source.replace("a,b", "a;b").replace("true,", "true")
    outcome = _candidate_preview(source, malicious)
    assert outcome["status"] == "llm_candidate_rejected"


@pytest.mark.asyncio
async def test_guard_loads_sealed_model_candidate_and_runs_staging_only(vault_env):
    put()
    calls = []
    class Edge:
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)
        async def config_validate(self, target, service):
            return {"success": True, "supported": True, "config_file": PATH,
                    "valid": False, "error_line": 5}
        async def _run(self, target, cmd, *, stdin_data=None):
            calls.append((cmd, stdin_data))
            return {"success": True, "stdout": base64.b64encode(SOURCE.encode()).decode()}
        async def _sudo(self, target, cmd, *, stdin_data=None):
            calls.append((cmd, stdin_data))
            return {"success": True, "stdout": "VALIDATED"}
    out = await run_governed_change(
        Edge(), action="validate", target=TARGET, service=SERVICE,
        config_file=PATH, original_sha256=HASH_SOURCE,
        candidate_sha256=HASH_CORRECTED, proposed_change="llm_full_file_repair",
    )
    assert out["success"] is True
    assert out["isolated_validation"] is True
    assert out["production_write_performed"] is False
    assert len(calls) == 2
    assert "/bin/sh -s -- validate nginx" in calls[1][0]
    assert base64.b64encode(CORRECTED.encode()).decode() in calls[1][1]
    assert CORRECTED not in str(out)
    assert CORRECTED not in calls[1][0]


@pytest.mark.asyncio
async def test_source_drift_blocks_before_sudo_even_with_sealed_candidate(vault_env):
    put()
    class Drift:
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)
        async def config_validate(self, *args):
            return {"success": True, "supported": True, "config_file": PATH}
        async def _run(self, *args):
            return {"success": True, "stdout": base64.b64encode(b"different source").decode()}
        async def _sudo(self, *args, **kwargs):
            raise AssertionError("must never reach privileged guard")
    result = await run_governed_change(
        Drift(), action="validate", target=TARGET, service=SERVICE,
        config_file=PATH, original_sha256=HASH_SOURCE,
        candidate_sha256=HASH_CORRECTED, proposed_change="llm_full_file_repair",
    )
    assert result["status"] == "live_source_or_candidate_drift"
    assert result["production_write_performed"] is False


def test_complete_file_llm_exfiltration_needs_explicit_sre_permission():
    from fastapi import HTTPException
    from apps.api.incident_chat import authorize_complete_file_disclosure
    tool = "service_config_llm_repair"
    assert authorize_complete_file_disclosure(tool, tool, ("sre",)) == tool
    assert authorize_complete_file_disclosure(tool, "answer", ("sre",)) == "answer"
    for roles in (("viewer",), ("operator",), (), ("viewer", "operator")):
        with pytest.raises(HTTPException) as denied:
            authorize_complete_file_disclosure(tool, tool, roles)
        assert denied.value.status_code == 403
    assert authorize_complete_file_disclosure(
        "service_config_review", "service_config_review", ("viewer",),
    ) == "service_config_review"


def test_llm_proposal_requires_sealed_worker_candidate():
    from apps.api.config_change_review import ConfigReviewResponse, _matching_proposal
    from apps.api.config_change_execution import _same_incident_candidate
    proposal = {
        "status": "candidate_proposed", "service": SERVICE,
        "config_file": PATH, "original_sha256": HASH_SOURCE,
        "candidate_sha256": HASH_CORRECTED,
        "proposed_change": "llm_full_file_repair",
        "candidate_stored": True, "validation_profile": "nginx",
        "source_evidence_refs": ["evidence:llm"],
        "execution_authority": False, "apply_eligible": False,
    }
    form = ConfigReviewResponse(
        decision="request_change_approval",
        expected_original_sha256=HASH_SOURCE,
        expected_candidate_sha256=HASH_CORRECTED,
    )
    assert _matching_proposal(proposal, form) is True
    assert not _matching_proposal({**proposal, "candidate_stored": False}, form)
    assert not _matching_proposal({**proposal, "validation_profile": "unregistered"}, form)
    assert not _matching_proposal({**proposal, "service": "haproxy"}, form)
    assert not _matching_proposal({**proposal, "candidate_sha256": "a" * 64}, form)
