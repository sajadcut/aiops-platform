"""LLM proposes field IDs; only literal, service-bound config values are used."""
import base64
import json
from types import SimpleNamespace

import pytest

from integrations.vm.dependency_llm_binding import resolve_llm_bindings
from integrations.vm import dependency_investigation as investigation


def _settings():
    return {
        "Redis": {
            "Endpoints": {"Primary": {"Host": "10.248.34.221"}},
            "ConnectionOptions": {"TcpPort": 6389, "Password": "TOP_SECRET_NEVER_SEND"},
            "Other": {"Account": "someone", "Username": "alice"},
        },
        "RabbitMQ": {"Host": "mq.internal", "Port": 5672},
    }


class Provider:
    def __init__(self, pairs):
        self.pairs = pairs
        self.messages = []
    async def generate_with_messages(self, messages, **kwargs):
        self.messages.append((messages, kwargs))
        return SimpleNamespace(content=json.dumps({"pairs": self.pairs}),
                               finish_reason="stop")


@pytest.mark.asyncio
async def test_llm_selects_real_redis_host_and_port_from_sanitized_tree():
    model = Provider([{"host_id": "h0", "port_id": "p0"}])
    result = await resolve_llm_bindings(_settings(), adapter=model)
    assert result["status"] == "verified"
    endpoint = result["endpoints"][0]
    assert endpoint["kind"] == "redis"
    assert endpoint["host"] == "10.248.34.221"
    assert endpoint["port"] == 6389
    assert endpoint["port_inferred"] is False
    assert endpoint["config_key"] == "Redis.Endpoints.Primary.Host"
    assert endpoint["config_port_key"] == "Redis.ConnectionOptions.TcpPort"
    assert endpoint["endpoint_source"] == "llm_binding_independently_verified"
    assert result["model_received_raw_config"] is False
    user_message = model.messages[0][0][1]["content"]
    assert "10.248.34.221" in user_message
    assert "6389" in user_message
    assert "TOP_SECRET_NEVER_SEND" not in user_message
    assert "alice" not in user_message
    assert "someone" not in user_message
    assert "Password" not in user_message
    assert model.messages[0][1]["stage"] == "dependency_config_field_binding"


@pytest.mark.asyncio
async def test_llm_cannot_provide_a_guessed_port_or_field_id():
    model = Provider([{"host_id": "h0", "port_id": "p99"}])
    result = await resolve_llm_bindings(_settings(), adapter=model)
    assert result["status"] == "llm_unsubstantiated_selection"
    assert result["endpoints"] == []


@pytest.mark.asyncio
async def test_llm_cannot_mix_redis_host_with_messaging_port():
    # h0 = Redis; p1 = RabbitMQ
    model = Provider([{"host_id": "h0", "port_id": "p1"}])
    result = await resolve_llm_bindings(_settings(), adapter=model)
    assert result["status"] == "llm_cross_dependency_selection"
    assert result["endpoints"] == []


@pytest.mark.asyncio
async def test_llm_refuses_ambiguous_multiple_sibling_ports():
    cfg = {"Redis": {
        "Endpoints": {"Primary": {"Host": "cache.local"}},
        "Network": {"PrimaryPort": 6389, "ReplicaPort": 6390},
    }}
    model = Provider([{"host_id": "h0", "port_id": "p0"}])
    result = await resolve_llm_bindings(cfg, adapter=model)
    assert result["status"] == "llm_cross_dependency_selection"
    assert result["endpoints"] == []


@pytest.mark.asyncio
async def test_model_unavailable_does_not_block_strict_config_parser(monkeypatch):
    class ProviderDown:
        async def generate_with_messages(self, *args, **kwargs):
            raise RuntimeError("unavailable")
    result = await resolve_llm_bindings(_settings(), adapter=ProviderDown())
    assert result["status"] == "llm_binding_unavailable"
    assert result["endpoints"] == []


@pytest.mark.asyncio
async def test_investigation_uses_llm_verified_6389_not_guessed_6379(monkeypatch):
    data = _settings()
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    probes = []
    from integrations.vm import dependency_llm_binding as binding
    model = Provider([{"host_id": "h0", "port_id": "p0"}])
    real = binding.resolve_llm_bindings
    async def resolve(config):
        return await real(config, adapter=model)
    monkeypatch.setattr(investigation, "resolve_llm_bindings", resolve)

    class Worker:
        def _validate_target(self, target): assert target == "vm"
        def _validate_service(self, service): assert service == "gfpapi"
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [
                {"path": "/srv/gfp/appsettings.json", "verified_exists": True},
            ]}
        async def _run(self, target, command):
            return {"success": True, "stdout": encoded}
        async def tcp_check(self, target, host, port):
            probes.append((host, port))
            return {"success": True, "supported": True,
                    "reachable": False}
        async def dns_check(self, *args):
            return {"success": True, "resolved": True}
        async def route_check(self, *args):
            return {"success": True, "route_found": True}

    result = await investigation.investigate(Worker(), "vm", "gfpapi")
    assert result["llm_field_binding_status"] == "verified"
    redis = [d for d in result["dependencies"] if d["kind"] == "redis"]
    assert len(redis) == 1
    assert redis[0]["host"] == "10.248.34.221"
    assert redis[0]["port"] == 6389
    assert redis[0]["config_port_key"] == "Redis.ConnectionOptions.TcpPort"
    assert redis[0]["tcp_reachable"] is False
    assert ("10.248.34.221", 6389) in probes
    assert ("10.248.34.221", 6379) not in probes
    assert "TOP_SECRET_NEVER_SEND" not in str(result)
