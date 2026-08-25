from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from apps.api.execution import _require_risk_permission
from apps.audit_service import AuditService
from domain.contracts.config import settings
from integrations.llm.mock_provider import MockLLMProvider


def test_audit_redacts_nested_secrets():
    AuditService.clear()
    event = AuditService.record(
        "security_test",
        "tester",
        metadata={
            "password": "secret-password",
            "nested": {"Authorization": "Bearer abc", "safe": "visible"},
            "api_key": "key-123",
        },
    )
    assert event.metadata["password"] == "[REDACTED]"
    assert event.metadata["nested"]["Authorization"] == "[REDACTED]"
    assert event.metadata["api_key"] == "[REDACTED]"
    assert event.metadata["nested"]["safe"] == "visible"


def test_high_risk_approval_requires_high_risk_role():
    operator = SimpleNamespace(roles=("operator",))
    with pytest.raises(HTTPException) as exc:
        _require_risk_permission(operator, "high")
    assert exc.value.status_code == 403


def test_sre_can_approve_high_risk():
    sre = SimpleNamespace(roles=("sre",))
    _require_risk_permission(sre, "high")


def test_mock_provider_cannot_be_constructed_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    with pytest.raises(RuntimeError, match="mock_llm_provider_forbidden_in_production"):
        MockLLMProvider()
