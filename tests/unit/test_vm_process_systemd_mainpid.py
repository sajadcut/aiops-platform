"""A service running as dotnet/java must not be misreported as down."""
import pytest
from integrations.vm.ssh_connector import SSHVMConnector


@pytest.mark.asyncio
async def test_systemd_mainpid_is_verified_when_process_comm_differs():
    commands = []
    class Worker:
        def _validate_service(self, process):
            assert process == "gfp_backend"
        async def _run(self, target, command):
            commands.append(command)
            if "ps -C" in command:
                return {"success": True, "stdout": ""}
            assert "ps -p 4044168" in command
            return {"success": True, "stdout": "4044168 1 S dotnet 1.2 4.1"}
        async def service_status(self, target, process):
            return {"success": True, "target": target, "service": process,
                    "unit_id": "gfp_backend.service", "main_pid": 4044168,
                    "load_state": "loaded", "active_state": "active"}

    result = await SSHVMConnector.process_status(Worker(), "vm-a", "gfp_backend")
    assert result["running"] is True
    assert result["processes"][0]["command"] == "dotnet"
    assert result["match_basis"] == "verified_systemd_main_pid"
    assert result["application_health_verified"] is False
    assert len(commands) == 2


@pytest.mark.asyncio
async def test_mismatched_unit_does_not_get_attributed_to_requested_service():
    class Worker:
        def _validate_service(self, process): pass
        async def _run(self, target, command):
            assert "ps -p" not in command
            return {"success": True, "stdout": ""}
        async def service_status(self, target, process):
            return {"success": True, "target": target, "unit_id": "gfpapi.service",
                    "main_pid": 4044168, "load_state": "loaded",
                    "active_state": "active"}

    result = await SSHVMConnector.process_status(Worker(), "vm-a", "gfp_backend")
    assert result["running"] is False
    assert result["match_basis"] == "process_comm"


@pytest.mark.asyncio
async def test_zombie_systemd_mainpid_is_not_running():
    class Worker:
        def _validate_service(self, process): pass
        async def _run(self, target, command):
            return {"success": True, "stdout": (
                "" if "ps -C" in command else "4044168 1 Z dotnet 0.0 0.0"
            )}
        async def service_status(self, target, process):
            return {"success": True, "target": target, "unit_id": "gfp_backend.service",
                    "main_pid": 4044168, "load_state": "loaded",
                    "active_state": "active"}
    result = await SSHVMConnector.process_status(Worker(), "vm-a", "gfp_backend")
    assert result["running"] is False
