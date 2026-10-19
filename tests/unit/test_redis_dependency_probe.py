"""Redis worker checks and evidence ledger contract."""
import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from integrations.vm.redis_dependency import parse_redis_endpoints, check_redis_config
from apps.incident_investigation_report import build_rows, explain


def test_redis_parser_never_collects_sql_or_secret():
    config = {
        "ConnectionStrings": {
            "Redis": "redis01.internal:6380,password=DO_NOT_ECHO,ssl=true",
            "PrimaryDb": "sql01.internal:1433,password=SECRET",
        },
        "Redis": {"Host": "10.10.20.30", "Port": 6390},
    }
    values = parse_redis_endpoints(config)
    assert values == [{"host": "redis01.internal", "port": 6380},
                      {"host": "10.10.20.30", "port": 6390}]
    assert "SECRET" not in repr(values)
    assert "sql01" not in repr(values)
    assert parse_redis_endpoints({"Redis": {"Configuration": "$" + "{REDIS_HOST}:6379"}}) == []


@pytest.mark.asyncio
async def test_read_only_redis_tcp_uses_only_systemd_verified_appsettings():
    encoded = base64.b64encode(json.dumps({
        "ConnectionStrings": {"Redis": "redis.internal:6380,password=DO_NOT_ECHO"}
    }).encode()).decode()
    class Stub:
        def _validate_service(self, service):
            assert service == "gfpapi"
        async def service_config_discovery(self, target, service):
            return {"success": True, "runtime": "dotnet", "files": [
                {"path": "/data/gfp/gfpapi/appsettings.json", "verified_exists": True},
            ]}
        async def _run(self, target, command):
            assert "/data/gfp/gfpapi/appsettings.json" in command
            return {"success": True, "stdout": encoded}
        async def tcp_check(self, target, host, port):
            assert (target, host, port) == ("10.248.16.82", "redis.internal", 6380)
            return {"success": True, "supported": True, "reachable": False}
    result = await check_redis_config(Stub(), "10.248.16.82", "gfpapi")
    assert result["status"] == "tcp_checked"
    assert result["endpoints"][0]["tcp_status"] == "unreachable"
    assert result["execution_authority"] is False
    assert result["application_health_verified"] is False
    assert result["root_cause_confirmed"] is False
    assert "DO_NOT_ECHO" not in repr(result)


@pytest.mark.asyncio
async def test_unverified_config_is_not_read():
    class Stub:
        def _validate_service(self, service): pass
        async def service_config_discovery(self, target, service):
            return {"success": True, "runtime": "unknown", "files": [
                {"path": "/etc/secrets/appsettings.json", "verified_exists": False},
            ]}
        async def _run(self, target, command):
            raise AssertionError("No remote read allowed")
    result = await check_redis_config(Stub(), "vm01", "gfpapi")
    assert result["status"] == "no_systemd_bound_appsettings"


def _brief():
    return {
        "snapshot_id": "v1",
        "mcp_evidence": [{
            "server": "elasticsearch", "tool": "source_observation",
            "status": "success", "phase": "live",
            "finding": "No decoded Redis log rows", "evidence_ref": "ev-01",
        }],
        "cognia_knowledge": {"status": "filtered_empty", "retrieved_count": 4,
                            "accepted_count": 0, "rejected_count": 4},
        "operational_memory": {"retrieved_count": 0},
        "agent_findings": [{"id": "fd-01", "agent": "dependency",
                            "statement": "Redis is a possible contributor"}],
    }


def test_ledger_keeps_evidence_refs_and_count():
    rows = build_rows(_brief())
    assert rows[0]["evidence_refs"] == ["ev-01"]
    assert any(x["id"] == "cognia" and "4" in x["result"] for x in rows)
    assert any(x["id"] == "memory" and "0" in x["result"] for x in rows)
    assert any(x["id"] == "agents" and x["status"] == "hypotheses" for x in rows)


@pytest.mark.asyncio
async def test_model_cannot_invent_rows_or_execution():
    response = {
        "notes": [{"id": "check-1", "note": "لاگ Elastic سلامت Redis را تأیید نمی‌کند."},
                  {"id": "invalid", "note": "Everything healthy"}],
        "conclusion": "علت قطعی اثبات نشده است.",
        "next_checks": [
            {"tool": "redis_dependency_check", "why": "بررسی Endpoint"},
            {"tool": "restart_service", "why": "restart now"},
        ],
    }
    llm = SimpleNamespace(generate_with_messages=AsyncMock(
        return_value=SimpleNamespace(content=json.dumps(response, ensure_ascii=False),
                                     finish_reason="stop")))
    result = await explain(_brief(), "fa", llm=llm)
    assert result["llm_status"] == "available"
    assert result["rows"][0]["llm_interpretation"]
    assert "Everything healthy" not in str(result)
    assert result["next_checks"] == [{
        "tool": "redis_dependency_check", "why": "بررسی Endpoint", "executed": False,
    }]
    assert result["execution_authority"] is False


@pytest.mark.asyncio
async def test_transport_failure_cannot_become_reachable_tcp():
    payload = base64.b64encode(json.dumps({
        "Redis": {"Host": "redis.internal", "Port": 6380}
    }).encode()).decode()

    class Stub:
        def _validate_service(self, service): pass
        async def service_config_discovery(self, target, service):
            return {"success": True, "runtime": "dotnet", "files": [
                {"path": "/srv/prod/appsettings.json", "verified_exists": True}
            ]}
        async def _run(self, target, command):
            return {"success": True, "stdout": payload}
        async def tcp_check(self, target, host, port):
            return {"success": False, "supported": True, "reachable": True}

    result = await check_redis_config(Stub(), "test-vm", "gfpapi")
    assert result["status"] == "tcp_unverified"
    assert result["endpoints"][0]["tcp_reachable"] is None
    assert result["application_health_verified"] is False


@pytest.mark.asyncio
async def test_systemd_dotnet_publish_directory_is_just_a_readonly_verified_path():
    from integrations.vm.ssh_connector import SSHVMConnector

    class Stub:
        def _validate_service(self, service):
            assert service == "gfpapi"
        async def service_runtime_discovery(self, target, service):
            return {"success": True, "runtime": "dotnet", "config_candidates": [],
                    "unit_file": "/etc/systemd/system/gfpapi.service",
                    "publish_directory": "/data/app/gfpapi",
                    "working_directory": None}
        async def _run(self, target, command):
            assert target == "test-vm"
            assert "/data/app/gfpapi/appsettings.json" in command
            assert "cat " not in command and "base64" not in command
            return {"success": True}

    result = await SSHVMConnector.service_config_discovery(Stub(), "test-vm", "gfpapi")
    assert result["success"] is True
    assert result["files"] == [{
        "path": "/data/app/gfpapi/appsettings.json",
        "source": "systemd_dotnet_publish",
        "status": "exists_readable", "verified_exists": True,
        "content_validated": False
    }]
    assert result["config_contents_exposed"] is False


@pytest.mark.asyncio
async def test_redis_alert_gets_bounded_dependency_check_without_model():
    from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner

    state = {"service_name": "gfpapi", "context": {"evidence": [{
        "source": "elasticsearch",
        "raw_data": {"message": "Redis timeout while connecting"},
        "type": "log",
    }]}}
    result = await DynamicInvestigationPlanner.propose(state, adapter=None)
    assert result["execution_authority"] is False
    assert result["checks"] == ["dependency_investigation"]
    requests = DynamicInvestigationPlanner.evidence_requests(
        result, has_service=True, has_port=False
    )
    assert len(requests) == 1
    assert requests[0]["evidence_type"] == "telemetry"
    assert "dependency" in requests[0]["reason"]
    assert DynamicInvestigationPlanner.evidence_requests(
        result, has_service=False, has_port=False
    ) == []


def test_incident_chat_explicit_redis_uses_read_only_intent():
    from apps.incident_copilot import fallback_intent, redis_dependency_answer

    assert fallback_intent("اتصال ردیس سرویس gfpapi رو بررسی زنده کن") == "dependency_investigation"
    assert fallback_intent("بررسی زنده Redis سرویس") == "dependency_investigation"
    response = redis_dependency_answer({
        "success": True, "status": "tcp_checked",
        "endpoints": [{"host": "redis.internal", "port": 6380,
                       "tcp_reachable": True}]
    })
    assert "redis.internal:6380" in response
    assert "سلامت Redis" in response
    assert "تأیید نشده" in response
