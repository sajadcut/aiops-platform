"""Exact alert service may map to a canonical unit only via live systemd Names."""
import pytest

from apps.signal_gateway import SignalGateway
from apps.context_service.service_identity import ServiceIdentityResolver
from domain.contracts.config import settings


@pytest.mark.asyncio
async def test_exact_gfp_backend_alert_only_follows_live_systemd_alias(monkeypatch):
    import apps.signal_gateway as gateway
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent_pull")
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {"10.248.16.82": "dummy-test-token"})
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES", {})
    monkeypatch.setattr(gateway, "vm_transport_configured", lambda: True)

    class Client:
        async def service_status(self, target, service):
            assert (target, service) == ("10.248.16.82", "GFP_Backend")
            return {
                "success": True, "target": target, "service": service,
                "unit_id": "gfpapi.service", "load_state": "loaded",
                "active_state": "active", "unit_aliases": [
                    "gfpapi.service", "GFP_Backend.service",
                ],
            }
        async def close(self):
            pass

    import integrations.vm.mcp_client as vmclient
    monkeypatch.setattr(vmclient, "VMEdgeMCPClient", Client)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "GFP_Backend-vm",
        "ip_addresses": ["10.248.16.82"],
    }]}
    rows = await SignalGateway._verify_elastic_host_candidate("GFP_Backend", discovery)
    assert discovery["status"] == "verified_by_vm_mcp"
    assert discovery["verified_runtime_service"] == "gfpapi"
    assert discovery["reported_log_service"] == "GFP_Backend"
    assert discovery["mapping_status"] == "verified_systemd_alias"
    assert rows[0]["raw_data"]["source_service_label"] == "GFP_Backend"
    mapping = {
        "source_service": "GFP_Backend",
        "runtime_service": "gfpapi",
        "target": "10.248.16.82",
        "evidence_reference": rows[0]["reference"],
        "verification": "vm_mcp_service_status",
    }
    assert ServiceIdentityResolver.verified_runtime_alias_matches(
        "GFP_Backend", "gfpapi",
        {"verified_runtime_mapping": mapping}, rows,
    )
    # A forged label and a mismatched evidence ref cannot authorize binding.
    bad = [dict(rows[0], raw_data={
        **rows[0]["raw_data"], "unit_aliases": ["gfpapi.service"],
    })]
    assert not ServiceIdentityResolver.verified_runtime_alias_matches(
        "GFP_Backend", "gfpapi",
        {"verified_runtime_mapping": mapping}, bad,
    )
    assert not ServiceIdentityResolver.verified_runtime_alias_matches(
        "GFP_Backend", "gfpapi",
        {"verified_runtime_mapping": {**mapping,
         "evidence_reference": "some-other-incident"}}, rows,
    )


@pytest.mark.asyncio
async def test_canonical_unit_mismatch_without_live_names_stays_unverified(monkeypatch):
    import apps.signal_gateway as gateway
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent_pull")
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {"10.248.16.82": "dummy-test-token"})
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES", {})
    monkeypatch.setattr(gateway, "vm_transport_configured", lambda: True)
    class Client:
        async def service_status(self, target, service):
            return {"success": True, "target": target, "service": service,
                    "unit_id": "gfpapi.service", "load_state": "loaded",
                    "active_state": "active", "unit_aliases": ["gfpapi.service"]}
        async def close(self):
            pass
    import integrations.vm.mcp_client as vmclient
    monkeypatch.setattr(vmclient, "VMEdgeMCPClient", Client)
    discovery = {"candidates": [{"hostname": "GFP_Backend-vm",
                                 "ip_addresses": ["10.248.16.82"]}]}
    rows = await SignalGateway._verify_elastic_host_candidate(
        "GFP_Backend", discovery)
    assert rows == []
    assert discovery["candidates"][0]["verification_status"] == "vm_canonical_unit_mismatch"
    assert not discovery.get("verified_runtime_service")
