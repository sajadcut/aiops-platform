from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"marker not found in {path}: {old[:120]!r}")
    if text.count(old) != 1:
        raise SystemExit(f"marker not unique in {path}: count={text.count(old)}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# Machine authentication response: tokenType is part of the documented contract.
replace(
    "integrations/cognia/client.py",
    '            token_type = str(payload.get("tokenType") or "Bearer").strip()\n',
    '            token_type = str(payload.get("tokenType") or "").strip()\n',
)
replace(
    "integrations/cognia/client.py",
    '            if not token or token_type.lower() != "bearer" or expires_in <= 0:\n',
    '            if not token or not token_type or token_type.lower() != "bearer" or expires_in <= 0:\n',
)

# Cognia documents relevanceScore as retrieval relevance, not a normalized probability.
Path("knowledge/retrieval_contract.py").write_text(
    '''import math\nfrom typing import Any, Dict\n\nBASE_REQUIRED = ("source_id", "provider", "relevance", "retrieved_at")\nCOGNIA_REQUIRED = (\n    "knowledge_base_id",\n    "knowledge_id",\n    "revision_id",\n    "revision_number",\n    "chunk_id",\n    "version",\n    "content",\n)\n\n\ndef validate_retrieval(item: Dict[str, Any]) -> bool:\n    if not all(key in item for key in BASE_REQUIRED):\n        return False\n    if str(item.get("provider") or "").strip().lower() != "cognia":\n        return False\n    try:\n        relevance = float(item.get("relevance"))\n    except (TypeError, ValueError):\n        return False\n    if not math.isfinite(relevance):\n        return False\n    return all(key in item and item.get(key) is not None for key in COGNIA_REQUIRED)\n''',
    encoding="utf-8",
)

replace(
    "apps/rag_service/__init__.py",
    "from datetime import datetime, timezone\nfrom typing import Any, Dict, List, Optional\n",
    "import math\nfrom datetime import datetime, timezone\nfrom typing import Any, Dict, List, Optional\n",
)
replace(
    "apps/rag_service/__init__.py",
    "        min_similarity: float = 0.5,\n",
    "        min_similarity: Optional[float] = None,\n",
)
replace(
    "apps/rag_service/__init__.py",
    '''        if not 0 <= min_similarity <= 1:\n            raise ValueError("knowledge_min_relevance_must_be_between_0_and_1")\n        return await self._search_cognia(\n            query,\n            limit=limit,\n            min_relevance=min_similarity,\n            scope_context=scope_context,\n        )\n''',
    '''        min_relevance: Optional[float] = None\n        if min_similarity is not None:\n            min_relevance = float(min_similarity)\n            if not math.isfinite(min_relevance):\n                raise ValueError("knowledge_min_relevance_must_be_finite")\n        return await self._search_cognia(\n            query,\n            limit=limit,\n            min_relevance=min_relevance,\n            scope_context=scope_context,\n        )\n''',
)
replace(
    "apps/rag_service/__init__.py",
    "        min_relevance: float,\n",
    "        min_relevance: Optional[float],\n",
)
replace(
    "apps/rag_service/__init__.py",
    '''            if not 0 <= relevance <= 1:\n                raise CogniaContractError("cognia_relevance_score_out_of_range")\n            if relevance < min_relevance:\n                continue\n''',
    '''            if not math.isfinite(relevance):\n                raise CogniaContractError("cognia_relevance_score_not_finite")\n            if min_relevance is not None and relevance < min_relevance:\n                continue\n''',
)
replace(
    "apps/orchestrator/e2e_graph.py",
    '''                    limit=settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS,\n                    min_similarity=0.5,\n                    scope_context=scope_context,\n''',
    '''                    limit=settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS,\n                    scope_context=scope_context,\n''',
)

replace(
    "tests/unit/test_cognia_rag_service.py",
    '''@pytest.mark.asyncio\nasync def test_cognia_relevance_threshold_is_retrieval_filter_not_probability(monkeypatch):\n    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])\n    monkeypatch.setattr(rag_module, "CogniaClient", FakeCogniaClient)\n    FakeCogniaClient.search_payload = {\n        "items": [\n            {\n                "rank": 1,\n                "relevanceScore": 0.49,\n                "knowledgeBaseId": 10,\n                "knowledgeId": 1,\n                "revisionId": 2,\n                "revisionNumber": 1,\n                "chunkId": 3,\n                "chunkText": "low retrieval relevance",\n            }\n        ]\n    }\n\n    assert await KnowledgeRAGService().search("query", min_similarity=0.5) == []\n''',
    '''@pytest.mark.asyncio\nasync def test_cognia_relevance_score_is_not_assumed_to_be_probability_range(monkeypatch):\n    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])\n    monkeypatch.setattr(rag_module, "CogniaClient", FakeCogniaClient)\n    FakeCogniaClient.search_payload = {\n        "items": [\n            {\n                "rank": 1,\n                "relevanceScore": 7.5,\n                "knowledgeBaseId": 10,\n                "knowledgeId": 1,\n                "revisionId": 2,\n                "revisionNumber": 1,\n                "chunkId": 3,\n                "chunkText": "provider-defined retrieval relevance",\n            }\n        ]\n    }\n\n    items = await KnowledgeRAGService().search("query")\n    assert items[0]["relevance"] == 7.5\n    assert await KnowledgeRAGService().search("query", min_similarity=8.0) == []\n''',
)

p = Path("tests/unit/test_cognia_client.py")
text = p.read_text(encoding="utf-8")
anchor = "\n\n@pytest.mark.asyncio\nasync def test_search_401_reauthenticates_once(monkeypatch):\n"
if anchor not in text:
    raise SystemExit("machine-token test anchor missing")
addition = '''\n\n@pytest.mark.asyncio\nasync def test_machine_token_requires_explicit_bearer_token_type(monkeypatch):\n    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)\n\n    def handler(request: httpx.Request) -> httpx.Response:\n        if request.url.path == "/api/access/client-auth/token":\n            return httpx.Response(200, json={"accessToken": "opaque", "expiresIn": 900})\n        return httpx.Response(500)\n\n    async with CogniaClient(\n        base_url="http://cognia.test",\n        client_id="app-token-type",\n        client_secret="secret",\n        transport=httpx.MockTransport(handler),\n    ) as client:\n        with pytest.raises(CogniaContractError, match="cognia_machine_token_response_invalid"):\n            await client.search("query", knowledge_base_ids=[10], limit=5)\n'''
p.write_text(text.replace(anchor, addition + anchor, 1), encoding="utf-8")

p = Path("tests/unit/test_cognia_client.py")
text = p.read_text(encoding="utf-8")
anchor = "\n\n@pytest.mark.asyncio\nasync def test_search_dependency_failure_propagates_without_fallback(monkeypatch):\n"
if anchor not in text:
    raise SystemExit("search-filter test anchor missing")
addition = '''\n\n@pytest.mark.asyncio\nasync def test_search_forwards_documented_filters_and_opaque_continuation(monkeypatch):\n    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)\n\n    def handler(request: httpx.Request) -> httpx.Response:\n        if request.url.path == "/api/access/client-auth/token":\n            return httpx.Response(200, json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900})\n        if request.url.path == "/api/engine/search":\n            assert json.loads(request.content) == {\n                "query": "runbook",\n                "knowledgeBaseIds": [10],\n                "limit": 20,\n                "continuationToken": "opaque-continuation",\n                "knowledgeType": "text",\n                "tagIds": [5, 8],\n                "categoryIds": [20],\n                "metadata": {"issuer": "central-bank"},\n            }\n            return httpx.Response(200, json={"items": [], "nextContinuationToken": None})\n        return httpx.Response(404)\n\n    async with CogniaClient(\n        base_url="http://cognia.test",\n        client_id="app-filters",\n        client_secret="secret",\n        transport=httpx.MockTransport(handler),\n    ) as client:\n        payload = await client.search(\n            "runbook",\n            knowledge_base_ids=[10],\n            limit=20,\n            continuation_token="opaque-continuation",\n            knowledge_type="text",\n            tag_ids=[5, 8],\n            category_ids=[20],\n            metadata={"issuer": "central-bank"},\n        )\n    assert payload["items"] == []\n'''
p.write_text(text.replace(anchor, addition + anchor, 1), encoding="utf-8")

p = Path("tests/unit/test_cognia_client.py")
text = p.read_text(encoding="utf-8")
anchor = "\n\n@pytest.mark.asyncio\nasync def test_context_requires_sufficiency_contract(monkeypatch):\n"
if anchor not in text:
    raise SystemExit("context-422 test anchor missing")
addition = '''\n\n@pytest.mark.asyncio\nasync def test_context_fail_generation_422_preserves_cognia_error_code(monkeypatch):\n    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 1)\n\n    def handler(request: httpx.Request) -> httpx.Response:\n        if request.url.path == "/api/access/client-auth/token":\n            return httpx.Response(200, json={"tokenType": "Bearer", "accessToken": "opaque", "expiresIn": 900})\n        if request.url.path == "/api/engine/context":\n            return httpx.Response(\n                422,\n                headers={"content-type": "application/problem+json"},\n                json={"status": 422, "code": "CONTEXT_INSUFFICIENT_KNOWLEDGE", "traceId": "ctx-422"},\n            )\n        return httpx.Response(404)\n\n    async with CogniaClient(\n        base_url="http://cognia.test",\n        client_id="app-context-422",\n        client_secret="secret",\n        transport=httpx.MockTransport(handler),\n    ) as client:\n        with pytest.raises(CogniaAPIError) as captured:\n            await client.generate_context("task", context_profile_id=501)\n    assert captured.value.status_code == 422\n    assert captured.value.code == "CONTEXT_INSUFFICIENT_KNOWLEDGE"\n    assert captured.value.trace_id == "ctx-422"\n'''
p.write_text(text.replace(anchor, addition + anchor, 1), encoding="utf-8")

replace(
    "MASTER.md",
    "| **Vector Store / pgvector** | **قطعی برای Memory** | **PostgreSQL + pgvector لایه Semantic Retrieval برای Operational Memory است؛ local Knowledge فقط dev/test compatibility است.** |",
    "| **Vector Store / pgvector** | **قطعی برای Memory** | **PostgreSQL + pgvector فقط لایه Semantic Retrieval برای Operational Memory است؛ هیچ local Knowledge RAG در هیچ environment وجود ندارد.** |",
)
replace(
    "docs/CONFIGURATION.md",
    "| `COGNIA_BASE_URL` | Cognia client/readiness | No | Required when Cognia is selected; production requires HTTPS. Do not hard-code the sandpod URL into production. |",
    "| `COGNIA_BASE_URL` | Cognia client/readiness | No | Required in production because Cognia is the only Knowledge RAG; production requires HTTPS. Do not hard-code the sandpod URL into production. |",
)
replace(
    "docs/CONFIGURATION.md",
    "| `COGNIA_CLIENT_SECRET` | Cognia Machine Authentication | **Yes** | Required for Cognia; secret manager only; never log, commit, audit or prompt. |\n| `COGNIA_KNOWLEDGE_BASE_IDS` | Cognia Search | No | Required non-empty positive explicit KB allowlist when Cognia is selected. Cognia still enforces effective `kb.read`. |",
    "| `COGNIA_CLIENT_SECRET` | Cognia Machine Authentication | **Yes** | Required for Cognia; secret manager only; never log, commit, audit or prompt. |\n| `COGNIA_CLIENT_APPLICATION_ID` | Cognia Scope / External Subject | No | Numeric Client Application identity; distinct from `COGNIA_CLIENT_ID`. Required only when ClientApplication/ExternalSubject scoped requests are used. |\n| `COGNIA_KNOWLEDGE_BASE_IDS` | Cognia Search | No | Required non-empty positive explicit KB allowlist in production. Cognia still enforces effective `kb.read` on every configured KB. |",
)
replace(
    "docs/CONFIGURATION.md",
    "- `aiops-platform-config`: non-secret runtime values, including `COGNIA_BASE_URL`, KB IDs, optional Context Profile ID, timeout and TLS policy.",
    "- `aiops-platform-config`: non-secret runtime values, including `COGNIA_BASE_URL`, `COGNIA_CLIENT_APPLICATION_ID` when scoped retrieval is used, KB IDs, optional Context Profile ID, timeout and TLS policy.",
)
replace(
    "docs/CONFIGURATION.md",
    "Cognia is the canonical Governed Knowledge RAG. `legacy provider selector=cognia` is mandatory for governed Production. The tracked non-secret development template uses `retired local Knowledge RAG` only so a clean checkout does not require real Cognia credentials. Production requires HTTPS, TLS verification, machine `COGNIA_CLIENT_ID`/`COGNIA_CLIENT_SECRET` and explicit `COGNIA_KNOWLEDGE_BASE_IDS`.",
    "Cognia is the only Governed Knowledge RAG in every environment. There is no runtime provider selector and no local/retired Knowledge RAG. Development/test may leave Cognia connection values empty so a clean checkout can import, but any attempted Knowledge retrieval fails explicitly as Cognia misconfiguration rather than switching providers. Production requires HTTPS, TLS verification, machine `COGNIA_CLIENT_ID`/`COGNIA_CLIENT_SECRET` and explicit `COGNIA_KNOWLEDGE_BASE_IDS`.",
)
replace(
    "tests/unit/test_cognia_only_rag_architecture.py",
    '        "local Knowledge pgvector only fixture",\n',
    '        "local Knowledge pgvector only fixture",\n        "local Knowledge فقط dev/test compatibility است",\n        "legacy provider selector=cognia",\n        "retired local Knowledge RAG",\n',
)
replace(
    "docs/COGNIA_INTEGRATION.md",
    "`relevanceScore` is retrieval relevance and never becomes factual confidence or live Evidence confidence.",
    "`relevanceScore` is retrieval relevance and never becomes factual confidence or live Evidence confidence. The supplied Cognia contract does not define it as a normalized 0..1 probability, so the default incident path does not impose a client-side normalization threshold; any explicit threshold must be justified by accepted environment evidence.",
)
replace(
    "docs/COGNIA_INTEGRATION.md",
    "No Subject is inferred from an Incident service/customer name. An upstream caller may provide `context.knowledge_subject` only as an explicit stable contract containing `namespace` and `externalSubjectId` (or the internal snake_case alias). The Search client adds the configured numeric Client Application ID and rejects a mismatched Client Application ID.",
    "No Subject is inferred from an Incident service/customer name. A trusted upstream integration may provide `context.knowledge_subject` only as an explicit stable contract containing `namespace` and `externalSubjectId` (or the internal snake_case alias). The Search client adds the configured numeric Client Application ID and rejects a mismatched Client Application ID. Client ownership is not a substitute for caller-to-Subject authorization; deployments using sensitive ExternalSubject scopes must bind the upstream caller/incident to that Subject before forwarding it.",
)
