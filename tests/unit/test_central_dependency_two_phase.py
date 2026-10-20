"""AIOps central LLM binding: field IDs are verified only on the VM worker."""
import base64
import json
from types import SimpleNamespace

import pytest

from integrations.vm import dependency_investigation
from integrations.vm.central_dependency import investigate_from_aiops
from integrations.vm.tool_contract import validate_vm_observation


class CentralModel:
    def __init__(self, choice):
        self.choice = choice
        self.calls = []
    async def generate_with_messages(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return SimpleNamespace(content=json.dumps(self.choice), finish_reason="stop")


class VerifiedWorker:
    def __init__(self, config):
        self.config = config
        self.probes = []
        self.phase_calls = []
    def _validate_target(self, target):
        assert target == "vm"
    def _validate_service(self, service):
        assert service == "GFP_Backend"
    async def service_config_discovery(self, target, service):
        return {"success": True, "files": [
            {"path": "/opt/GFP/appsettings.json", "verified_exists": True},
        ]}
    async def _run(self, target, command):
        return {"success": True, "stdout": base64.b64encode(
            json.dumps(self.config).encode("utf-8")).decode("ascii")}
    async def tcp_check(self, target, host, port):
        self.probes.append((host, port))
        return {"success": True, "supported": True, "reachable": False}
    async def dns_check(self, target, host):
        return {"success": True, "resolved": False}
    async def dependency_investigation(self, target, service, *,
                                       mode="probe", selections=None,
                                       priority_family=""):
        self.phase_calls.append((mode, priority_family, selections))
        result = await dependency_investigation.investigate(
            self, target, service, mode=mode,
            selections=selections, priority_family=priority_family,
        )
        return validate_vm_observation("dependency_investigation", target, result)


@pytest.mark.asyncio
async def test_central_model_binds_db_port_from_config_and_worker_probes_only_db_first():
    worker = VerifiedWorker({
        "Redis": {"Host": "redis.internal", "Port": 6389},
        "Database": {"Connection": {"Host": "pg.internal", "Port": 6439},
                     "Password": "TOP_SECRET_NEVER_SEND"},
    })
    # Candidates' order: Redis=h0/p0, Database=h1/p1.
    model = CentralModel({"pairs": [{"host_id": "h1", "port_id": "p1"}],
                          "endpoint_ids": []})
    result = await investigate_from_aiops(
        worker, "vm", "GFP_Backend", priority_family="database", adapter=model,
    )
    assert result["llm_field_binding_status"] == "verified"
    assert ("pg.internal", 6439) in worker.probes
    assert worker.probes[0] == ("pg.internal", 6439)
    assert result["dependencies"][0]["config_port_key"] == "Database.Connection.Port"
    assert result["dependencies"][0]["endpoint_source"] == "llm_binding_independently_verified"
    assert [phase for phase, _, _ in worker.phase_calls] == ["discover", "probe"]
    prompt = str(model.calls[0][0])
    assert "TOP_SECRET_NEVER_SEND" not in prompt
    assert model.calls[0][1]["stage"] == "central_dependency_config_binding"
    assert "TOP_SECRET_NEVER_SEND" not in str(result)
    assert len(worker.phase_calls[1][2]) == 1
    assert all("host" not in selection and "port" not in selection
               for selection in worker.phase_calls[1][2])


@pytest.mark.asyncio
async def test_changed_config_sha_blocks_model_selected_endpoint():
    worker = VerifiedWorker({"Database": {"Host": "db.internal", "Port": 5439}})
    discovery = await worker.dependency_investigation(
        "vm", "GFP_Backend", mode="discover")
    assert discovery["binding_candidates"][0]["host_fields"][0]["host"] == "db.internal"
    assert discovery["checks_executed"] == 0
    choice = [{
        "file_index": 0,
        "sha256": discovery["binding_candidates"][0]["sha256"],
        "pairs": [{"host_id": "h0", "port_id": "p0"}],
        "endpoint_ids": [],
    }]
    worker.config = {"Database": {"Host": "another.internal", "Port": 6439}}
    result = await worker.dependency_investigation(
        "vm", "GFP_Backend", selections=choice, priority_family="database")
    assert result["llm_field_binding_status"] == "config_changed"
    assert not worker.probes
    assert result["checks_executed"] == 0
    assert result["dependencies"] == []


@pytest.mark.asyncio
async def test_unavailable_central_model_still_probes_literal_db_uri_without_guessing():
    worker = VerifiedWorker({
        "ConnectionStrings": {"Primary": "postgresql://alice:password@pg.internal:6543/main"},
    })
    result = await investigate_from_aiops(
        worker, "vm", "GFP_Backend", priority_family="database",
    )
    assert ("pg.internal", 6543) in worker.probes
    assert ("pg.internal", 5432) not in worker.probes
    assert result["llm_field_binding_status"] in {
        "central_llm_unavailable", "no_model_match", "verified",
    }
    assert "password" not in str(result)


@pytest.mark.asyncio
async def test_invalid_model_pair_not_used_as_network_destination():
    worker = VerifiedWorker({
        "Redis": {"Host": "redis.internal", "Port": 6389},
        "Database": {"Host": "db.internal", "Port": 5549},
    })
    model = CentralModel({"pairs": [{"host_id": "h99", "port_id": "p0"}],
                          "endpoint_ids": []})
    result = await investigate_from_aiops(
        worker, "vm", "GFP_Backend", priority_family="database", adapter=model,
    )
    assert result["llm_field_binding_status"] == "central_llm_unavailable"
    assert ("db.internal", 5549) in worker.probes
    assert all(host in {"redis.internal", "db.internal"} for host, _ in worker.probes)


@pytest.mark.asyncio
async def test_projection_rejects_unexpected_raw_config_value():
    worker = VerifiedWorker({"Database": {"Host": "db.internal", "Port": 5549}})
    discovery = await dependency_investigation.investigate(
        worker, "vm", "GFP_Backend", mode="discover")
    discovery["binding_candidates"][0]["raw_config"] = "secret bytes"
    with pytest.raises(ValueError, match="vm_mcp_dependency_candidate_shape_invalid"):
        validate_vm_observation("dependency_investigation", "vm", discovery)


@pytest.mark.asyncio
async def test_old_vm_agent_with_single_phase_probes_reports_upgrade_not_llm_failure():
    class LegacyWorker:
        async def dependency_investigation(self, target, service, **kwargs):
            assert target == "vm" and service == "GFP_Backend"
            return {
                "success": True, "status": "checks_completed",
                "config_files_checked": 4,
                "llm_field_binding_status": "trusted_llm_not_configured",
                "llm_field_binding_files": [{
                    "status": "trusted_llm_not_configured",
                    "candidate_host_count": 6, "candidate_port_count": 6,
                }],
                "dependencies": [{
                    "kind": "redis", "host": "cache.internal",
                    "port": 6380, "port_inferred": False,
                    "tcp_reachable": True,
                }],
                "limitations": ["network_probe_not_equal_protocol_health"],
            }
    result = await investigate_from_aiops(
        LegacyWorker(), "vm", "GFP_Backend", priority_family="database",
        adapter=CentralModel({"pairs": [], "endpoint_ids": []}),
    )
    assert result["dependency_agent_contract_status"] == "upgrade_required"
    assert result["llm_field_binding_status"] == "agent_upgrade_required"
    assert result["root_cause_confirmed"] is False
    assert result["status"] == "checks_completed"  # raw tool result retained
    assert "two_phase_central_llm_agent_contract_missing" in result["limitations"]
    assert result["dependencies"][0]["kind"] == "redis"  # unrelated evidence


@pytest.mark.asyncio
async def test_old_worker_without_new_python_parameters_is_explicitly_flagged():
    class VeryOldWorker:
        async def dependency_investigation(self, target, service):
            return {"success": True, "status": "checks_completed"}
    result = await investigate_from_aiops(
        VeryOldWorker(), "vm", "GFP_Backend", priority_family="database",
    )
    assert result["llm_field_binding_status"] == "agent_upgrade_required"
    assert result["dependency_agent_contract_status"] == "upgrade_required"
    assert result["root_cause_confirmed"] is False
