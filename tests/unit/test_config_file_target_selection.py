"""Never send or repair an unrelated JSON data file for a measured .NET failure."""
from __future__ import annotations

import base64

import pytest

from integrations.vm.ssh_connector import SSHVMConnector


def _connector(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    monkeypatch.setattr(connector, "_validate_target", lambda target: None)
    monkeypatch.setattr(connector, "_validate_service", lambda service: None)
    async def validator(target, service):
        return {"success": True, "supported": False, "config_file": None}
    async def discovery(target, service):
        return {"success": True, "runtime": "dotnet",
                "files": [
                    {"path": "/data/gfp/gfpapi/MessageTemplates.json",
                     "verified_exists": True},
                    {"path": "/data/gfp/gfpapi/appsettings.json",
                     "verified_exists": True},
                ]}
    monkeypatch.setattr(connector, "config_validate", validator)
    monkeypatch.setattr(connector, "service_config_discovery", discovery)
    return connector


@pytest.mark.asyncio
async def test_explicit_full_file_llm_receives_verified_appsettings_not_first_json(monkeypatch):
    from integrations.vm import full_config_llm_repair as mod
    connector = _connector(monkeypatch)
    seen = []
    monkeypatch.setattr(
        mod.settings, "AIOPS_FULL_CONFIG_LLM_ENABLED", True
    )
    async def read(target, command):
        seen.append(("read", command))
        return {"success": True, "stdout": base64.b64encode(
            b'{"app":"gfpapi", bad_key:true}'
        ).decode()}
    async def repair(encoded, **kwargs):
        seen.append(("repair", kwargs))
        assert kwargs["path"] == "/data/gfp/gfpapi/appsettings.json"
        assert base64.b64decode(encoded).startswith(b'{"app":"gfpapi"')
        return {"status": "llm_candidate_proposed", "success": True,
                "source_hash": "a"*64, "candidate_hash": "b"*64}
    monkeypatch.setattr(connector, "_run", read)
    monkeypatch.setattr(mod, "review_complete_config", repair)
    result = await connector.service_config_llm_repair("10.248.16.82", "gfpapi")
    assert result["config_file"] == "/data/gfp/gfpapi/appsettings.json" if "config_file" in result else True
    assert result["selected_by"] == "verified_dotnet_appsettings"
    assert len(seen) == 2
    assert "/MessageTemplates.json" not in seen[0][1]


@pytest.mark.asyncio
async def test_primary_broken_appsettings_never_replaced_with_unrelated_patch(monkeypatch):
    connector = _connector(monkeypatch)
    reads = []
    async def discovery(target, service):
        return {"success": True, "runtime": "dotnet", "files": [
            {"path": "/data/gfp/gfpapi/appsettings.json", "verified_exists": True},
            {"path": "/data/gfp/gfpapi/MessageTemplates.json", "verified_exists": True},
        ]}
    async def read(target, command):
        reads.append(command)
        # Multiple missing quotes cannot be fixed with one grammar token.
        data = '{"enabled":true, broken-!:3, other-!:4}'
        return {"success": True, "stdout": base64.b64encode(data.encode()).decode()}
    monkeypatch.setattr(connector, "service_config_discovery", discovery)
    monkeypatch.setattr(connector, "_run", read)
    result = await connector.service_config_review("10.248.16.82", "gfpapi")
    assert result["config_file"] == "/data/gfp/gfpapi/appsettings.json"
    assert result["status"] == "syntax_invalid_no_safe_candidate"
    assert result["candidate_hash"] is None
    assert result["apply_eligible"] is False
    assert len(reads) == 1  # Never prefer MessageTemplates while appsettings is broken.
