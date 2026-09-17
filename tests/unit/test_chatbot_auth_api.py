from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.chatbot import router
from domain.contracts.config import settings
from domain.contracts.rate_limit import rate_limiter_strict


app = FastAPI()
app.include_router(router, prefix="/api/v1")
client = TestClient(app)


def _configure(monkeypatch, role: str):
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", "chatbot-test-key")
    monkeypatch.setattr(settings, "INTERNAL_API_ROLE", role)
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", None)
    monkeypatch.setattr(settings, "OIDC_AUDIENCE", None)
    monkeypatch.setattr(settings, "OIDC_JWKS_URL", None)


def test_chatbot_me_requires_authentication(monkeypatch):
    _configure(monkeypatch, "viewer")
    assert client.get("/api/v1/chatbot/me").status_code == 401
    assert client.get("/api/v1/chatbot/me", headers={"X-API-Key": "wrong"}).status_code == 401


def test_viewer_can_login_but_only_has_read_permissions(monkeypatch):
    _configure(monkeypatch, "viewer")
    response = client.get("/api/v1/chatbot/me", headers={"X-API-Key": "chatbot-test-key"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["subject"] == "api-key"
    assert payload["roles"] == ["viewer"]
    assert "read:incident" in payload["permissions"]
    assert "execute:approved" not in payload["permissions"]
    assert "approve:high_risk" not in payload["permissions"]


def test_operator_can_login_without_high_risk_execution(monkeypatch):
    _configure(monkeypatch, "operator")
    response = client.get("/api/v1/chatbot/me", headers={"X-API-Key": "chatbot-test-key"})
    assert response.status_code == 200
    permissions = set(response.json()["permissions"])
    assert "read:incident" in permissions
    assert "approve:low_risk" in permissions
    assert "approve:high_risk" not in permissions
    assert "execute:approved" not in permissions


def test_sre_can_login_with_existing_high_risk_approval_and_execution_permissions(monkeypatch):
    _configure(monkeypatch, "sre")
    response = client.get("/api/v1/chatbot/me", headers={"X-API-Key": "chatbot-test-key"})
    assert response.status_code == 200
    permissions = set(response.json()["permissions"])
    assert {"read:incident", "approve:high_risk", "execute:approved"} <= permissions


def test_chatbot_message_stream_and_action_decision_use_strict_rate_limiter():
    protected_paths = {
        "/chatbot/message",
        "/chatbot/message/stream",
        "/chatbot/actions/{proposal_id}/decision",
    }
    routes = [route for route in router.routes if route.path in protected_paths]
    assert {route.path for route in routes} == protected_paths
    for route in routes:
        dependency_calls = {dependency.call for dependency in route.dependant.dependencies}
        assert rate_limiter_strict in dependency_calls
