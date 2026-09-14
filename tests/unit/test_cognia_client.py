import json

import httpx
import pytest

from domain.contracts.config import settings
from integrations.cognia import CogniaAPIError, CogniaClient, CogniaConfigurationError, CogniaContractError


def _search_response():
    return {
        "items": [
            {
                "rank": 1,
                "relevanceScore": 0.92,
                "knowledgeBaseId": 10,
                "knowledgeId": 9001,
                "revisionId": 12001,
                "revisionNumber": 3,
                "chunkId": 501,
                "chunkIndex": 7,
                "chunkText": "bounded operational guidance",
                "startOffset": 1200,
                "endOffset": 1580,
                "approximateTokenCount": 110,
                "knowledgeType": "text",
                "scope": {"type": "general"},
            }
        ],
        "nextContinuationToken": None,
    }


@pytest.mark.asyncio
async def test_machine_token_is_opaque_cached_and_search_contract_is_exact(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)
    calls = {"auth": 0, "search": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            calls["auth"] += 1
            assert json.loads(request.content) == {"clientId": "app-1", "clientSecret": "secret-1"}
            return httpx.Response(
                200,
                json={
                    "tokenType": "Bearer",
                    "accessToken": "opaque-token-without-jwt-semantics",
                    "expiresIn": 900,
                },
            )
        if request.url.path == "/api/engine/search":
            calls["search"] += 1
            assert request.headers["authorization"] == "Bearer opaque-token-without-jwt-semantics"
            body = json.loads(request.content)
            assert body == {
                "query": "database connection exhaustion",
                "knowledgeBaseIds": [10, 20],
                "limit": 5,
                "scopeContext": {
                    "clientApplicationId": 42,
                    "subjectNamespace": "service",
                    "externalSubjectId": "payments",
                },
            }
            return httpx.Response(200, json=_search_response())
        return httpx.Response(404)

    client = CogniaClient(
        base_url="http://cognia.test",
        client_id="app-1",
        client_secret="secret-1",
        transport=httpx.MockTransport(handler),
    )
    try:
        for _ in range(2):
            payload = await client.search(
                "database connection exhaustion",
                knowledge_base_ids=[10, 20],
                limit=5,
                scope_context={
                    "clientApplicationId": 42,
                    "subjectNamespace": "service",
                    "externalSubjectId": "payments",
                },
            )
            assert payload["items"][0]["chunkId"] == 501
        assert calls == {"auth": 1, "search": 2}
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_search_401_reauthenticates_once(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)
    calls = {"auth": 0, "search": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            calls["auth"] += 1
            return httpx.Response(
                200,
                json={"tokenType": "Bearer", "accessToken": f"token-{calls['auth']}", "expiresIn": 900},
            )
        if request.url.path == "/api/engine/search":
            calls["search"] += 1
            if calls["search"] == 1:
                assert request.headers["authorization"] == "Bearer token-1"
                return httpx.Response(
                    401,
                    headers={"content-type": "application/problem+json"},
                    json={"status": 401, "code": "FAILED_AUTHENTICATION", "traceId": "trace-1"},
                )
            assert request.headers["authorization"] == "Bearer token-2"
            return httpx.Response(200, json=_search_response())
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app-1",
        client_secret="secret-1",
        transport=httpx.MockTransport(handler),
    ) as client:
        payload = await client.search("query", knowledge_base_ids=[10], limit=5)

    assert payload["items"]
    assert calls == {"auth": 2, "search": 2}


@pytest.mark.asyncio
async def test_search_dependency_failure_propagates_without_fallback(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            return httpx.Response(
                200,
                json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900},
            )
        if request.url.path == "/api/engine/search":
            return httpx.Response(
                503,
                headers={"content-type": "application/problem+json"},
                json={
                    "status": 503,
                    "code": "SEARCH_DEPENDENCY_UNAVAILABLE",
                    "traceId": "trace-search",
                    "detail": "must not be used for branching",
                },
            )
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app-1",
        client_secret="secret-1",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CogniaAPIError) as captured:
            await client.search("query", knowledge_base_ids=[10], limit=5)

    assert captured.value.status_code == 503
    assert captured.value.code == "SEARCH_DEPENDENCY_UNAVAILABLE"
    assert captured.value.trace_id == "trace-search"


@pytest.mark.asyncio
async def test_context_200_may_be_insufficient(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            return httpx.Response(
                200,
                json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900},
            )
        if request.url.path == "/api/engine/context":
            assert json.loads(request.content) == {
                "contextProfileId": 501,
                "task": "collect incident guidance",
                "subject": {"namespace": "service", "externalSubjectId": "payments"},
            }
            return httpx.Response(
                200,
                json={
                    "contextProfileId": 501,
                    "contextProfileVersion": 4,
                    "isSufficient": False,
                    "totalTokenBudget": 1000,
                    "totalUsedTokens": 120,
                    "sections": [],
                },
            )
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app-1",
        client_secret="secret-1",
        transport=httpx.MockTransport(handler),
    ) as client:
        payload = await client.generate_context(
            "collect incident guidance",
            context_profile_id=501,
            subject={"namespace": "service", "externalSubjectId": "payments"},
        )

    assert payload["isSufficient"] is False


@pytest.mark.asyncio
async def test_context_requires_sufficiency_contract(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            return httpx.Response(
                200,
                json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900},
            )
        if request.url.path == "/api/engine/context":
            return httpx.Response(200, json={"sections": []})
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app-1",
        client_secret="secret-1",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CogniaContractError, match="cognia_context_is_sufficient_missing"):
            await client.generate_context("task", context_profile_id=501)


@pytest.mark.asyncio
async def test_registration_uses_idempotency_and_rejects_scope_spoof(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            return httpx.Response(200, json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900})
        if request.url.path == "/api/engine/knowledge-bases/10/knowledge":
            captured["idempotency"] = request.headers.get("idempotency-key")
            captured["body"] = json.loads(request.content)
            return httpx.Response(201, json={"knowledgeId": 9001, "revisionId": 12001, "revisionNumber": 1})
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app-credential",
        client_secret="secret",
        client_application_id=42,
        transport=httpx.MockTransport(handler),
    ) as client:
        created = await client.register_knowledge(
            knowledge_base_id=10,
            title="Runbook",
            content="safe content",
            scope={
                "type": "externalSubject",
                "clientApplicationId": 42,
                "subjectNamespace": "service",
                "externalSubjectId": "payments",
            },
            metadata={"source": "runbook"},
            idempotency_key="incident-runbook-001",
        )
        assert created["revisionNumber"] == 1
        with pytest.raises(CogniaConfigurationError, match="scope_spoof_rejected"):
            await client.register_knowledge(
                knowledge_base_id=10,
                title="Runbook",
                content="safe content",
                scope={"type": "clientApplication", "clientApplicationId": 99},
                idempotency_key="different",
            )

    assert captured["idempotency"] == "incident-runbook-001"
    assert captured["body"]["scope"]["externalSubjectId"] == "payments"


@pytest.mark.asyncio
async def test_candidate_revision_conflict_is_not_blindly_retried(monkeypatch):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 5)
    calls = {"revision": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/access/client-auth/token":
            return httpx.Response(200, json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900})
        if request.url.path.endswith("/knowledge/9001/revisions"):
            calls["revision"] += 1
            body = json.loads(request.content)
            assert "expectedCurrentCandidateRevisionId" in body
            return httpx.Response(
                409,
                headers={"content-type": "application/problem+json"},
                json={"status": 409, "code": "KNOWLEDGE_REVISION_CONCURRENCY_CONFLICT"},
            )
        return httpx.Response(404)

    async with CogniaClient(
        base_url="http://cognia.test",
        client_id="app",
        client_secret="secret",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CogniaAPIError) as captured:
            await client.create_revision(
                knowledge_base_id=10,
                knowledge_id=9001,
                expected_current_candidate_revision_id=None,
                title="v2",
                content="new content",
            )
    assert captured.value.code == "KNOWLEDGE_REVISION_CONCURRENCY_CONFLICT"
    assert calls["revision"] == 1


def test_machine_client_does_not_expose_human_approval_decisions():
    assert not hasattr(CogniaClient, "approve_revision")
    assert not hasattr(CogniaClient, "reject_revision")
