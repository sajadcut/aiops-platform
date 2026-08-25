from pathlib import Path

from domain.contracts.config import settings
from integrations.mcp_client import MCPClient


def test_signal_correlation_contract_is_bounded():
    assert settings.SIGNAL_CORRELATION_ENABLED is True
    assert 1 <= settings.SIGNAL_CORRELATION_WINDOW_SECONDS <= 3600
    assert 1 <= settings.SIGNAL_CORRELATION_CANDIDATE_LIMIT <= 100


def test_signal_gateway_uses_exact_and_cross_source_transaction_locks():
    source = Path("apps/signal_gateway/__init__.py").read_text(encoding="utf-8")
    assert 'event:{signal.source}:{signal.source_id}' in source
    assert 'correlation:{correlation.fingerprint}' in source
    assert "find_correlated_open_incident" in source
    assert "signal.timestamp - timedelta" in source


def test_correlation_repository_uses_postgresql_transaction_advisory_lock():
    source = Path("apps/incident_service/repository.py").read_text(encoding="utf-8")
    assert "pg_advisory_xact_lock" in source
    assert "IncidentStatus.OPEN" in source
    assert "IncidentStatus.ANALYZING" in source


def test_legacy_mcp_transport_is_explicitly_non_production():
    assert MCPClient.production_supported is False
    source = Path("integrations/mcp_client.py").read_text(encoding="utf-8")
    for required in (
        "legacy non-production transport",
        "OAuth 2.1",
        "resource/audience binding",
        "workload identity/mTLS",
        "Tool Registry / Policy / Approval / Audit",
    ):
        assert required in source
