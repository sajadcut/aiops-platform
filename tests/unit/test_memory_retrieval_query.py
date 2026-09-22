from apps.orchestrator.e2e_graph import E2EOrchestrator


def test_operational_memory_query_uses_live_symptoms_but_not_raw_secrets():
    query = E2EOrchestrator._operational_memory_query(
        service="nginx",
        base_query="NeoBanking port 86 is down token=base-query-secret",
        context={
            "incident": {
                "summary": "NeoBanking port 86 is down password=incident-secret",
                "severity": "Average",
            },
            "trigger_signal": {
                "signal_type": "problem",
                "trigger": "Authorization: Bearer trigger-secret",
                "target_ip": "10.100.6.199",
                "target_port": 86,
                "item_key": "net.tcp.port[10.100.6.199,86]",
            },
        },
        live_evidence={
            "evidence": [
                {
                    "source": "vm_mcp",
                    "raw_data": {
                        "diagnostic": "service_status",
                        "service": "nginx",
                        "target": "10.100.6.199",
                        "active_state": "inactive",
                        "healthy": False,
                        "password": "must-never-enter-query",
                        "raw_log": "Authorization: Bearer must-never-enter-query",
                    },
                },
                {
                    "source": "vm_mcp",
                    "raw_data": {
                        "diagnostic": "port_listener_status",
                        "target": "10.100.6.199",
                        "port": 86,
                        "listening": False,
                    },
                },
                {
                    "source": "vm_mcp",
                    "raw_data": {
                        "diagnostic": "tcp_check",
                        "target": "10.100.6.199",
                        "port": 86,
                        "reachable": False,
                    },
                },
            ]
        },
    )

    assert "nginx" in query
    assert "target_port=86" in query
    assert "active_state=inactive" in query
    assert "listening=False" in query
    assert "reachable=False" in query
    assert "must-never-enter-query" not in query
    assert "base-query-secret" not in query
    assert "incident-secret" not in query
    assert "trigger-secret" not in query
    assert "Bearer trigger-secret" not in query
    assert "[REDACTED]" in query
    assert len(query) <= 4000
