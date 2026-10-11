"""Local Windows launcher preflight never migrates or leaks DSNs."""
from pathlib import Path

import pytest

from scripts import check_database_migrations as checker


def test_matching_schema_exits_successfully(capsys):
    result = checker.migration_preflight_result({
        "valid": True, "expected_heads": ["l9m0n1o2p3q4"],
        "current_heads": ["l9m0n1o2p3q4"], "error": None,
    })
    assert result == 0
    assert "DATABASE_MIGRATION_OK" in capsys.readouterr().out


def test_stale_schema_explains_safe_real_migration_without_stamping(capsys):
    result = checker.migration_preflight_result({
        "valid": False, "expected_heads": ["l9m0n1o2p3q4"],
        "current_heads": ["k8h9i0j1k2l3"], "error": None,
    })
    output = capsys.readouterr().out
    assert result == 3
    assert "DATABASE_MIGRATION_DRIFT" in output
    assert "k8h9i0j1k2l3" in output and "l9m0n1o2p3q4" in output
    assert "verified database backup" in output
    assert "alembic.ini upgrade head" in output
    assert "Do not use 'alembic stamp head'" in output


def test_database_connection_exception_does_not_leak_credentials(monkeypatch, capsys):
    async def broken_db():
        raise RuntimeError("postgresql://secret:supersecret@internal.example:5432/db")
    monkeypatch.setattr(checker, "inspect_migrations", broken_db)
    result = checker.main()
    output = capsys.readouterr().out
    assert result == 4
    assert "DATABASE_PREFLIGHT_UNAVAILABLE" in output
    assert "RuntimeError" in output
    assert "supersecret" not in output
    assert "internal.example" not in output


def test_windows_launcher_runs_read_only_preflight_before_mcp_or_api_startup():
    source = Path("start-all.ps1").read_text(encoding="utf-8")
    assert "-m scripts.check_database_migrations" in source
    assert source.index("-m scripts.check_database_migrations") < source.index("Start-ManagedService $vm")
    assert "migrationPreflightExit -ne 0" in source
    assert "no migration was applied automatically" in source
    assert "alembic upgrade" not in source


def test_dashboard_error_explains_migration_drift_without_bypassing_guard():
    dashboard = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    room = Path("dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert "DATABASE_MIGRATION_DRIFT" in dashboard
    assert "DATABASE_MIGRATION_DRIFT" in room
    assert "پس از تهیه بکاپ" in dashboard
    assert "Alembic migration" in room
    assert "migration validation" not in room.lower() or "disable" not in room.lower()
