"""Read-only Cognia API contract checks from the consumer Postman collection."""
import json

import httpx
import pytest

from domain.contracts.config import settings
from integrations.cognia import CogniaClient, CogniaContractError
from scripts.verify_cognia_connection import run_probe


@pytest.mark.asyncio
async def test_machine_auth_kb_and_empty_search(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_BASE_URL", "http://cognia.test")
    monkeypatch.setattr(settings, "COGNIA_CLIENT_ID", "test-client")
    monkeypatch.setattr(settings, "COGNIA_CLIENT_SECRET", "test-credential")
    monkeypatch.setattr(settings, "COGNIA_CLIENT_APPLICATION_ID", 2)
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [1])
    monkeypatch.setattr(settings, "COGNIA_CONTEXT_PROFILE_ID", None)
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)
    paths = []

    def handler(req):
        paths.append((req.method, req.url.path))
        if req.url.path == "/api/access/client-auth/token":
            assert json.loads(req.content) == {
                "clientId": "test-client", "clientSecret": "test-credential"
            }
            return httpx.Response(200, json={
                "tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900
            })
        assert req.headers["authorization"] == "Bearer opaque"
        if req.url.path == "/api/engine/knowledge-bases/1":
            return httpx.Response(200, json={"id": 1, "isActive": True})
        if req.url.path == "/api/engine/search":
            assert json.loads(req.content) == {
                "query": "gfpapi", "knowledgeBaseIds": [1], "limit": 5
            }
            return httpx.Response(200, json={"items": [], "nextContinuationToken": None})
        raise AssertionError("unexpected Cognia endpoint")

    def factory():
        return CogniaClient(
            base_url="http://cognia.test", client_id="test-client",
            client_secret="test-credential", transport=httpx.MockTransport(handler),
        )

    result, exit_code = await run_probe(query="gfpapi", client_factory=factory)
    assert exit_code == 0
    assert result["auth"]["status"] == "passed"
    assert result["knowledge_bases"] == [{"id": 1, "status": "passed", "active": True}]
    assert result["search"]["status"] == "empty"
    assert "test-credential" not in json.dumps(result)
    assert "opaque" not in json.dumps(result)
    assert paths == [
        ("POST", "/api/access/client-auth/token"),
        ("GET", "/api/engine/knowledge-bases/1"),
        ("POST", "/api/engine/search"),
    ]
    _, strict_exit = await run_probe(query="gfpapi", require_results=True, client_factory=factory)
    assert strict_exit == 3


@pytest.mark.asyncio
async def test_explicit_null_subject_matches_postman(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)

    def handler(req):
        if req.url.path == "/api/access/client-auth/token":
            return httpx.Response(200, json={
                "tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900
            })
        assert json.loads(req.content) == {
            "contextProfileId": 51, "task": "investigate", "subject": None
        }
        return httpx.Response(200, json={"isSufficient": False, "sections": []})

    async with CogniaClient(
        base_url="http://cognia.test", client_id="id", client_secret="credential",
        transport=httpx.MockTransport(handler),
    ) as client:
        payload = await client.generate_context("investigate", context_profile_id=51)
    assert payload["isSufficient"] is False


@pytest.mark.asyncio
async def test_kb_get_rejects_wrong_identity(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)

    def handler(req):
        if req.url.path == "/api/access/client-auth/token":
            return httpx.Response(200, json={
                "tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900
            })
        return httpx.Response(200, json={"id": 9, "isActive": True})

    async with CogniaClient(
        base_url="http://cognia.test", client_id="id", client_secret="credential",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CogniaContractError, match="identity_or_activity_invalid"):
            await client.get_knowledge_base(1)
