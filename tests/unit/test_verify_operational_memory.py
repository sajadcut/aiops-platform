import pytest

import scripts.verify_operational_memory as verifier


@pytest.mark.asyncio
async def test_verify_memory_exit_codes(monkeypatch, capsys):
    async def healthy(_limit):
        return {
            "migration": {"valid": True},
            "stats": {"entries_total": 1},
            "latest": [],
        }

    monkeypatch.setattr(verifier, "inspect", healthy)
    assert await verifier.main(10, require_entry=True) == 0
    assert '"entries_total": 1' in capsys.readouterr().out

    async def empty(_limit):
        return {
            "migration": {"valid": True},
            "stats": {"entries_total": 0},
            "latest": [],
        }

    monkeypatch.setattr(verifier, "inspect", empty)
    assert await verifier.main(10, require_entry=False) == 0
    assert await verifier.main(10, require_entry=True) == 3

    async def drift(_limit):
        return {
            "migration": {"valid": False, "reason": "head_mismatch"},
            "stats": {"entries_total": 4},
            "latest": [],
        }

    monkeypatch.setattr(verifier, "inspect", drift)
    assert await verifier.main(10, require_entry=True) == 2
