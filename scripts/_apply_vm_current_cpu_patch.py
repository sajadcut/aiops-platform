from pathlib import Path


path = Path("integrations/vm/ssh_connector.py")
text = path.read_text(encoding="utf-8")
start = text.index("    async def collect_metrics(self, target: str) -> Dict[str, Any]:")
end = text.index("    async def host_info(self, target: str) -> Dict[str, Any]:", start)
replacement = '''    @staticmethod
    def _parse_cpu_counters(value: str) -> tuple[int, ...]:
        parts = value.split()
        if len(parts) != 8:
            raise ValueError("invalid_cpu_counter_sample")
        counters = tuple(int(part) for part in parts)
        if any(counter < 0 for counter in counters):
            raise ValueError("invalid_cpu_counter_sample")
        return counters

    @classmethod
    def _cpu_interval_percentages(cls, first: str, second: str) -> tuple[float, float]:
        start = cls._parse_cpu_counters(first)
        end = cls._parse_cpu_counters(second)
        deltas = tuple(after - before for before, after in zip(start, end))
        if any(delta < 0 for delta in deltas):
            raise ValueError("cpu_counter_reset")
        total_delta = sum(deltas)
        if total_delta <= 0:
            raise ValueError("cpu_counter_delta_zero")
        idle_delta = deltas[3] + deltas[4]
        busy_delta = total_delta - idle_delta
        if busy_delta < 0:
            raise ValueError("invalid_cpu_counter_delta")
        cpu_usage = round((busy_delta * 100.0) / total_delta, 2)
        io_wait = round((deltas[4] * 100.0) / total_delta, 2)
        return cpu_usage, io_wait

    async def collect_metrics(self, target: str) -> Dict[str, Any]:
        command = (
            "LC_ALL=C; "
            "printf 'CPU1 '; awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8,$9; exit}' /proc/stat; "
            "sleep 1; "
            "printf 'CPU2 '; awk '/^cpu / {print $2,$3,$4,$5,$6,$7,$8,$9; exit}' /proc/stat; "
            "free | awk '/^Mem:/ {printf \\\"MEM %.2f\\\\n\\\", ($3/$2)*100} /^Swap:/ {if ($2>0) printf \\\"SWAP %.2f\\\\n\\\", ($3/$2)*100; else printf \\\"SWAP 0.00\\\\n\\\"}'; "
            "awk '{printf \\\"LOAD %s,%s,%s\\\\n\\\", $1,$2,$3}' /proc/loadavg"
        )
        result = await self._run(target, command)
        if not result.get("success"):
            return {"success": False, "target": target, "error": "ssh_command_failed", "execution_time": result.get("execution_time")}
        try:
            fields: Dict[str, str] = {}
            for raw_line in str(result.get("stdout") or "").splitlines():
                key, separator, value = raw_line.strip().partition(" ")
                if separator and key in {"CPU1", "CPU2", "MEM", "SWAP", "LOAD"}:
                    fields[key] = value.strip()
            if set(fields) != {"CPU1", "CPU2", "MEM", "SWAP", "LOAD"}:
                raise ValueError("missing_metric_fields")
            cpu_usage, io_wait = self._cpu_interval_percentages(fields["CPU1"], fields["CPU2"])
            memory_usage = round(float(fields["MEM"]), 2)
            swap_usage = round(float(fields["SWAP"]), 2)
            if not 0.0 <= memory_usage <= 100.0 or not 0.0 <= swap_usage <= 100.0:
                raise ValueError("invalid_memory_metric")
            payload = {
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "swap_usage": swap_usage,
                "load_avg": fields["LOAD"],
                "io_wait": io_wait,
            }
        except (TypeError, ValueError):
            return {"success": False, "target": target, "error": "invalid_metric_payload"}
        return {"success": True, "target": target, "metrics": payload, "execution_time": result.get("execution_time")}

'''
path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


test_path = Path("tests/unit/test_vm_current_cpu_metrics.py")
test_path.write_text(
    '''import pytest

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
                "CPU1 100 0 50 850 10 0 0 0\\n"
                "CPU2 120 0 60 920 20 0 0 0\\n"
                "MEM 62.50\\n"
                "SWAP 0.00\\n"
                "LOAD 0.82,0.91,0.76\\n"
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
                "CPU1 120 0 60 920 20 0 0 0\\n"
                "CPU2 100 0 50 850 10 0 0 0\\n"
                "MEM 50.00\\n"
                "SWAP 0.00\\n"
                "LOAD 0.10,0.10,0.10\\n"
            ),
            "execution_time": 1.01,
        }

    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.collect_metrics("vm01")
    assert result == {"success": False, "target": "vm01", "error": "invalid_metric_payload"}
''',
    encoding="utf-8",
)
