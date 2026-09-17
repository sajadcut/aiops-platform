import pytest

from domain.contracts.config import settings
from integrations.vm.ssh_connector import SSHVMConnector


def _connector(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "key")
    return SSHVMConnector(timeout=2)


def test_cpu_interval_percentages_use_delta_not_since_boot():
    cpu_usage, io_wait = SSHVMConnector._cpu_interval_percentages(
        "100 0 50 850 10 0 0 0",
        "120 0 60 920 20 0 0 0",
    )
    assert cpu_usage == pytest.approx(27.27, abs=0.01)
    assert io_wait == pytest.approx(9.09, abs=0.01)


@pytest.mark.asyncio
async def test_collect_metrics_returns_one_second_current_cpu(monkeypatch):
    connector = _connector(monkeypatch)
    captured = {}

    async def fake_run(target, command):
        captured["target"] = target
        captured["command"] = command
        return {
            "success": True,
            "stdout": (
                "CPU1 100 0 50 850 10 0 0 0\n"
                "CPU2 120 0 60 920 20 0 0 0\n"
                "MEM 62.50\n"
                "SWAP 0.00\n"
                "LOAD 0.82,0.91,0.76\n"
            ),
            "execution_time": 1.03,
        }

    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.collect_metrics("10.100.6.199")

    assert result["success"] is True
    assert result["target"] == "10.100.6.199"
    assert result["metrics"] == {
        "cpu_usage": pytest.approx(27.27, abs=0.01),
        "memory_usage": 62.5,
        "swap_usage": 0.0,
        "load_avg": "0.82,0.91,0.76",
        "io_wait": pytest.approx(9.09, abs=0.01),
    }
    assert "sleep 1" in captured["command"]
    assert captured["target"] == "10.100.6.199"


@pytest.mark.asyncio
async def test_collect_metrics_fails_closed_on_counter_reset(monkeypatch):
    connector = _connector(monkeypatch)

    async def fake_run(target, command):
        return {
            "success": True,
            "stdout": (
                "CPU1 120 0 60 920 20 0 0 0\n"
                "CPU2 100 0 50 850 10 0 0 0\n"
                "MEM 50.00\n"
                "SWAP 0.00\n"
                "LOAD 0.10,0.10,0.10\n"
            ),
            "execution_time": 1.01,
        }

    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.collect_metrics("vm01")
    assert result == {"success": False, "target": "vm01", "error": "invalid_metric_payload"}
