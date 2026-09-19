from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_major_outbound_integrations_have_semantic_latency_components():
    expected = {
        "integrations/llm/openai_compatible.py": 'component=f"llm:{self.provider_name}"',
        "integrations/mcp_client.py": 'component=f"mcp:{self.server_name}"',
        "integrations/cognia/client.py": 'component="cognia"',
        "integrations/prometheus/client.py": 'component="prometheus"',
        "integrations/elasticsearch/client.py": 'component="elasticsearch"',
        "integrations/kubernetes/client.py": 'component="kubernetes"',
        "knowledge/__init__.py": 'component="embedding"',
        "agents/shared/a2a_agent.py": 'component=f"a2a:{self.card.name}"',
        "apps/security/token_validator.py": 'component="oidc_jwks"',
    }
    missing = {
        path: token
        for path, token in expected.items()
        if token not in _read(path)
    }
    assert not missing, f"missing semantic outbound latency tags: {missing}"


def test_llm_logs_per_request_and_total_generation_latency():
    source = _read("integrations/llm/openai_compatible.py")
    assert 'action="chat_completion_completed"' in source
    assert 'action="chat_completion_failed"' in source
    assert '"duration_ms": round((time.perf_counter() - started) * 1000, 3)' in source
    assert 'action="llm_generation_completed"' in source
    assert 'action="llm_generation_failed"' in source
    assert '"total_duration_ms": round((time.perf_counter() - generation_started) * 1000, 3)' in source


def test_orchestrator_analysis_phases_publish_duration_ms():
    base = _read("apps/orchestrator/e2e_graph.py")
    signal = _read("apps/orchestrator/signal_aware.py")

    for event in (
        '"context_loaded"',
        '"triage_completed"',
        '"specialist_analysis_completed"',
        '"rca_completed"',
        '"evaluation_completed"',
    ):
        assert event in base

    assert base.count('duration_ms=round((time.perf_counter() - phase_started) * 1000, 3)') >= 5
    assert signal.count('duration_ms=round((time.perf_counter() - phase_started) * 1000, 3)') >= 2


def test_mcp_server_and_vm_ssh_publish_server_side_latency():
    mcp_server = _read("apps/mcp_server/main.py")
    ssh = _read("integrations/vm/ssh_connector.py")

    assert '"mcp_tool_call_completed"' in mcp_server
    assert '"mcp_tool_call_failed"' in mcp_server
    assert '"mcp_tool_call_denied"' in mcp_server
    assert "duration_ms=round((time.perf_counter() - tool_started) * 1000, 3)" in mcp_server

    assert '"vm_ssh_command_completed"' in ssh
    assert '"vm_ssh_command_timeout"' in ssh
    assert '"vm_ssh_command_failed"' in ssh
    assert "duration_ms=duration_ms" in ssh


def test_latency_logging_does_not_log_http_query_headers_or_body():
    source = _read("integrations/http_transport.py")
    assert '"outbound_http_completed"' in source
    assert '"outbound_http_failed"' in source
    assert '"duration_ms"' in source
    assert '"path": parsed.path or "/"' in source
    assert "parsed.query" not in source
    assert "request.headers" not in source
    assert "request.content" not in source
