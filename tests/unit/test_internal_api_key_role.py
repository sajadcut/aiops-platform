import pytest

from apps.security.auth import _identity_from_api_key
from domain.contracts.config import settings


def test_internal_api_key_uses_server_configured_role(monkeypatch):
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(settings, "INTERNAL_API_ROLE", "operator")
    identity = _identity_from_api_key("secret")
    assert identity is not None
    assert identity.roles == ("operator",)


def test_invalid_internal_api_role_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(settings, "INTERNAL_API_ROLE", "admin")
    with pytest.raises(RuntimeError, match="invalid_internal_api_role"):
        _identity_from_api_key("secret")


def test_wrong_internal_api_key_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(settings, "INTERNAL_API_ROLE", "operator")
    assert _identity_from_api_key("wrong") is None
