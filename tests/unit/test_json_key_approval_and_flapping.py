"""Crash-loop correlation and governed, single-token JSON repair regressions."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrations.vm.json_syntax_candidate import deterministic_json_syntax_fix
from integrations.vm.general_config_review import local_config_review
from integrations.vm.governed_config_change import rebuild_json_candidate
from integrations.vm.full_config_llm_repair import review_complete_config


def _sample(time, active, sub, restarts, *, target="10.248.16.82", service="gfpapi"):
    return {
        "source": "vm_mcp",
        "created_at": time,
        "reference": f"test:{time}",
        "raw_data": {
            "diagnostic": "service_status",
            "target": target, "service": service, "success": True,
            "active_state": active, "sub_state": sub, "result": "success",
            "restart_count": restarts,
            "main_pid": 123 if active == "active" else 0,
        },
    }


def test_recent_auto_restart_overrides_momentary_active_running_card():
    from apps.api.incident_chat import _observed_status

    samples = [
        _sample("2026-10-16T07:52:01Z", "active", "running", 119),
        _sample("2026-10-16T07:56:30Z", "activating", "auto-restart", 150),
        _sample("2026-10-16T07:58:12Z", "active", "running", 155),
    ]
    found = _observed_status("gfpapi", "10.248.16.82", samples, [])
    assert found["status"] == "unstable"
    assert found["active_state"] == "active"  # Preserve last exact observation.
    assert found["stability_reason"] == "auto_restart_cycle_observed"
    assert found["restart_count"] == 155
    assert found["application_health_verified"] is False
    assert found["verified_systemd_only"] is True


def test_single_old_restart_counter_is_not_proof_of_current_failure():
    from apps.api.incident_chat import _observed_status

    found = _observed_status("gfpapi", "10.248.16.82", [
        _sample("2026-10-16T07:52:01Z", "active", "running", 120)
    ], [])
    assert found["status"] == "running"
    assert found["application_health_verified"] is False


def test_auto_restart_state_alone_never_becomes_running():
    from apps.api.incident_chat import _observed_status

    found = _observed_status("gfpapi", "10.248.16.82", [
        _sample("2026-10-16T07:58:35Z", "activating", "auto-restart", 156)
    ], [])
    assert found["status"] == "unstable"
    assert found["active_state"] == "activating"
    assert found["main_pid"] == 0


def test_old_auto_restart_does_not_permanently_mark_running_as_unstable():
    from apps.api.incident_chat import _observed_status

    samples = [
        _sample("2026-10-16T07:40:00Z", "activating", "auto-restart", 10),
        _sample("2026-10-16T08:10:00Z", "active", "running", 10),
    ]
    assert _observed_status("gfpapi", "10.248.16.82", samples, [])["status"] == "running"


def test_json_microfix_accepts_one_bare_key_or_one_trailing_comma_only():
    assert deterministic_json_syntax_fix('{"enabled":true,\n retryCount:3}\n') == (
        '{"enabled":true,\n "retryCount":3}\n')
    assert deterministic_json_syntax_fix('{"enabled":true,}\n') == '{"enabled":true}\n'
    assert deterministic_json_syntax_fix('{"a":1,"b":2}') is None
    assert deterministic_json_syntax_fix('{"a":1, retry:2, second:3}') is None
    assert deterministic_json_syntax_fix('{"a":1,\n "b":}') is None


def test_default_config_review_proposes_json_key_quote_without_llm_or_remote_python():
    original = '{"enabled":true,\n retryCount:3}\n'
    result = local_config_review(
        base64.b64encode(original.encode()).decode(),
        path="/data/gfp/gfpapi/appsettings.json",
    )
    expected = '{"enabled":true,\n "retryCount":3}\n'
    assert result["status"] == "candidate_proposed"
    assert result["proposed_change"] == "quote_unquoted_json_key"
    assert result["validation_status"] == "FORMAT_CANDIDATE_VALID_ONLY"
    assert result["candidate_hash"] == hashlib.sha256(expected.encode()).hexdigest()
    assert result["source_hash"] == hashlib.sha256(original.encode()).hexdigest()
    assert result["config_contents_exposed"] is False
    assert result["apply_eligible"] is False


def test_governed_json_rebuild_matches_original_hash_and_rejects_drift():
    original = '{"enabled":true,\n retryCount:3}\n'
    candidate = deterministic_json_syntax_fix(original)
    assert candidate is not None
    kw = {
        "encoded": base64.b64encode(original.encode()).decode(),
        "path": "/data/gfp/gfpapi/appsettings.json",
        "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
        "proposed_change": "quote_unquoted_json_key",
    }
    assert rebuild_json_candidate(**kw) == candidate
    with pytest.raises(ValueError, match="config_source_hash_drift"):
        rebuild_json_candidate(**{**kw, "original_sha256": "a" * 64})
    with pytest.raises(ValueError, match="config_candidate_hash_mismatch"):
        rebuild_json_candidate(**{**kw, "candidate_sha256": "a" * 64})
    with pytest.raises(ValueError, match="config_change_not_deterministic"):
        rebuild_json_candidate(**{**kw, "proposed_change": "remove_trailing_json_comma"})


@pytest.mark.asyncio
async def test_unrelated_llm_edit_never_sealed_but_local_json_microfix_can_be(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair

    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://trusted.example")
    corrected = json.dumps({f"k{i:02}": i for i in range(45)}, indent=2) + "\n"
    original = corrected.replace('"k40"', 'k40')
    unrelated = original.replace('"k01": 1,', '"k01": 1,,')
    assert unrelated != original

    class FakeModel:
        async def generate(self, prompt, **kwargs):
            assert json.loads(prompt)["vendor_error_line"] == 42
            return SimpleNamespace(
                content=json.dumps({"corrected_config": unrelated}),
                finish_reason="stop",
            )

    stored = []

    def seal(**kwargs):
        stored.append(kwargs)
        return {"candidate_stored": True}

    monkeypatch.setattr(repair, "store_candidate", seal)
    result = await review_complete_config(
        base64.b64encode(original.encode()).decode(),
        service="gfpapi", path="/data/gfp/gfpapi/appsettings.json",
        target="10.248.16.82", model=FakeModel(),
    )
    assert result["status"] == "llm_candidate_proposed"
    assert result["candidate_origin"] == "deterministic_json_syntax"
    assert result["candidate_stored"] is True
    assert result["candidate_hash"] == hashlib.sha256(corrected.encode()).hexdigest()
    assert len(stored) == 1
    assert stored[0]["candidate"] == corrected  # Not the unrelated model output.
    assert result["execution_authority"] is False
    assert result["apply_eligible"] is False
    assert "k40" not in json.dumps(result)


@pytest.mark.asyncio
async def test_json_repair_rejects_two_errors_without_creating_a_ticket(monkeypatch):
    from integrations.vm import full_config_llm_repair as repair
    monkeypatch.setattr(repair.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True)
    monkeypatch.setattr(repair.settings, "LLM_BASE_URL", "https://trusted.example")
    source = '{"a":1, bad:2, other:3}\n'

    class FakeModel:
        async def generate(self, prompt, **kwargs):
            return SimpleNamespace(
                content=json.dumps({"corrected_config": source.replace("bad", "worse")}),
                finish_reason="stop",
            )

    def forbid(**kwargs):
        raise AssertionError("unsafe candidate sealed")

    monkeypatch.setattr(repair, "store_candidate", forbid)
    result = await review_complete_config(
        base64.b64encode(source.encode()).decode(),
        service="gfpapi", path="/data/gfp/gfpapi/appsettings.json",
        target="10.248.16.82", model=FakeModel(),
    )
    assert result["status"] != "llm_candidate_proposed"
    assert result["candidate_stored"] is False


def test_incident_room_exposes_restart_loop_instead_of_healthy_badge():
    source = (Path(__file__).resolve().parents[2]
              / "dashboards" / "incident-command-room.js").read_text(encoding="utf-8")
    assert "unstable:fa?'سرویس ناپایدار" in source
    assert "o.restart_count" in source
