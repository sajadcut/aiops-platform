from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"marker not found in {path}: {old[:120]!r}")
    if text.count(old) != 1:
        raise SystemExit(f"marker not unique in {path}: count={text.count(old)}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# Public workflow context must not become arbitrary ExternalSubject authority.
Path("apps/api/cognia_scope.py").write_text(
    '''from __future__ import annotations\n\nfrom typing import Any, Mapping\n\nfrom fastapi import HTTPException\n\n\ndef reject_untrusted_knowledge_subject(context: Mapping[str, Any] | None) -> None:\n    \"\"\"Reject caller-supplied Cognia ExternalSubject scope on public workflow APIs.\n\n    The AIOps service uses one Cognia Machine Client identity. A public caller's\n    ability to read an Incident does not prove that caller is authorized for an\n    arbitrary customer/account/case ExternalSubject. Trusted server-side\n    integrations may bind a Subject after their own domain authorization; public\n    free-form context cannot manufacture that authority.\n    \"\"\"\n    if not context:\n        return\n    if \"knowledge_subject\" in context or \"knowledgeSubject\" in context:\n        raise HTTPException(\n            status_code=403,\n            detail=\"knowledge_subject_requires_trusted_server_binding\",\n        )\n''',
    encoding="utf-8",
)

replace(
    "apps/api/e2e_workflow.py",
    "from apps.security.rbac import allowed\n",
    "from apps.security.rbac import allowed\nfrom apps.api.cognia_scope import reject_untrusted_knowledge_subject\n",
)
replace(
    "apps/api/e2e_workflow.py",
    '''    \"\"\"Run the guarded durable incident lifecycle without bypassing Decision/Approval.\"\"\"\n    try:\n''',
    '''    \"\"\"Run the guarded durable incident lifecycle without bypassing Decision/Approval.\"\"\"\n    reject_untrusted_knowledge_subject(request.context)\n    try:\n''',
)
replace(
    "apps/api/workflow.py",
    "from apps.security.auth import require_permission\n",
    "from apps.security.auth import require_permission\nfrom apps.api.cognia_scope import reject_untrusted_knowledge_subject\n",
)
replace(
    "apps/api/workflow.py",
    '''    \"\"\"Compatibility analysis endpoint backed by the canonical durable E2E runtime.\"\"\"\n    incident_id = request.incident_id or str(uuid4())\n''',
    '''    \"\"\"Compatibility analysis endpoint backed by the canonical durable E2E runtime.\"\"\"\n    reject_untrusted_knowledge_subject(request.context)\n    incident_id = request.incident_id or str(uuid4())\n''',
)

Path("tests/unit/test_cognia_scope_guard.py").write_text(
    '''import pytest\nfrom fastapi import HTTPException\n\nfrom apps.api.cognia_scope import reject_untrusted_knowledge_subject\n\n\ndef test_public_workflow_context_allows_non_scope_metadata():\n    reject_untrusted_knowledge_subject({\"service\": \"payments\", \"trace\": \"abc\"})\n\n\n@pytest.mark.parametrize(\"key\", [\"knowledge_subject\", \"knowledgeSubject\"])\ndef test_public_workflow_context_rejects_untrusted_external_subject(key):\n    with pytest.raises(HTTPException) as captured:\n        reject_untrusted_knowledge_subject(\n            {key: {\"namespace\": \"customer\", \"externalSubjectId\": \"C-9381\"}}\n        )\n    assert captured.value.status_code == 403\n    assert captured.value.detail == \"knowledge_subject_requires_trusted_server_binding\"\n''',
    encoding="utf-8",
)

# Complete the service-level optimistic-concurrency flow without forcing callers
# to bypass the Cognia-only abstraction and instantiate the raw client.
needle = '''    async def create_revision(\n        self,\n        *,\n        knowledge_base_id: int,\n'''
insert = '''    async def get_knowledge_detail(\n        self, *, knowledge_base_id: int, knowledge_id: int\n    ) -> Dict[str, Any]:\n        kb_id = self._ensure_configured_kb(knowledge_base_id)\n        knowledge = int(knowledge_id)\n        if knowledge <= 0:\n            raise ValueError(\"cognia_knowledge_id_must_be_positive\")\n        async with CogniaClient() as client:\n            return await client.get_knowledge_detail(\n                knowledge_base_id=kb_id,\n                knowledge_id=knowledge,\n            )\n\n''' + needle
replace("apps/rag_service/__init__.py", needle, insert)

replace(
    "tests/unit/test_cognia_rag_service.py",
    '''    async def generate_context(self, task, **kwargs):\n        return {\"isSufficient\": False, \"task\": task, **kwargs}\n''',
    '''    async def generate_context(self, task, **kwargs):\n        return {\"isSufficient\": False, \"task\": task, **kwargs}\n\n    async def get_knowledge_detail(self, **kwargs):\n        type(self).captured = dict(kwargs)\n        return {\"knowledgeId\": kwargs[\"knowledge_id\"], \"currentCandidateRevisionId\": 12001}\n''',
)
anchor = '''\n\n@pytest.mark.asyncio\nasync def test_context_generation_uses_configured_profile(monkeypatch):\n'''
addition = '''\n\n@pytest.mark.asyncio\nasync def test_get_knowledge_detail_stays_inside_configured_cognia_kb(monkeypatch):\n    monkeypatch.setattr(settings, \"COGNIA_KNOWLEDGE_BASE_IDS\", [10])\n    monkeypatch.setattr(rag_module, \"CogniaClient\", FakeCogniaClient)\n\n    result = await KnowledgeRAGService().get_knowledge_detail(\n        knowledge_base_id=10,\n        knowledge_id=9001,\n    )\n\n    assert FakeCogniaClient.captured == {\"knowledge_base_id\": 10, \"knowledge_id\": 9001}\n    assert result[\"currentCandidateRevisionId\"] == 12001\n\n\n@pytest.mark.asyncio\nasync def test_get_knowledge_detail_rejects_unconfigured_kb(monkeypatch):\n    monkeypatch.setattr(settings, \"COGNIA_KNOWLEDGE_BASE_IDS\", [10])\n    monkeypatch.setattr(rag_module, \"CogniaClient\", FakeCogniaClient)\n\n    with pytest.raises(ValueError, match=\"knowledge_base_not_configured\"):\n        await KnowledgeRAGService().get_knowledge_detail(knowledge_base_id=20, knowledge_id=9001)\n'''
replace("tests/unit/test_cognia_rag_service.py", anchor, addition + anchor)

# Eliminate stale wording that implies a local Knowledge embedding/RAG path.
replace(
    "knowledge/__init__.py",
    '''    \"\"\"Provider-neutral embedding service for Knowledge RAG and Memory.\n\n    ``deterministic`` is intentionally available for tests and offline\n    development. Production refuses that provider and requires an explicitly\n    configured OpenAI-compatible internal/offline embedding gateway.\n    \"\"\"\n''',
    '''    \"\"\"Provider-neutral embedding service for Operational Memory only.\n\n    Cognia owns all Governed Knowledge retrieval and its embeddings/index are\n    never produced by this service. ``deterministic`` remains available only for\n    tests/offline development of Operational Memory; Production requires an\n    explicitly configured OpenAI-compatible internal/offline embedding gateway.\n    \"\"\"\n''',
)
replace(
    "integrations/cognia/client.py",
    '''class CogniaConfigurationError(RuntimeError):\n    \"\"\"Raised when the Cognia integration is selected but not safely configured.\"\"\"\n''',
    '''class CogniaConfigurationError(RuntimeError):\n    \"\"\"Raised when the sole Cognia Knowledge RAG boundary is not safely configured.\"\"\"\n''',
)

# MASTER must describe routes that actually exist. Cognia authoring remains an
# internal/direct governed Cognia capability, not a fictional AIOps proxy route.
replace(
    "MASTER.md",
    "| GET/POST | /api/v1/knowledge | مدیریت Knowledge documents |",
    "| GET | /api/v1/incidents/{id}/knowledge | بازیابی Governed Knowledge از Cognia برای Incident؛ Authoring/Revision از Cognia consumer API/internal service انجام می‌شود |",
)

replace(
    "docs/COGNIA_INTEGRATION.md",
    "No Subject is inferred from an Incident service/customer name. A trusted upstream integration may provide `context.knowledge_subject` only as an explicit stable contract containing `namespace` and `externalSubjectId` (or the internal snake_case alias). The Search client adds the configured numeric Client Application ID and rejects a mismatched Client Application ID. Client ownership is not a substitute for caller-to-Subject authorization; deployments using sensitive ExternalSubject scopes must bind the upstream caller/incident to that Subject before forwarding it.",
    "No Subject is inferred from an Incident service/customer name. Public `/workflow/analyze` and `/workflow/e2e` requests reject caller-supplied `knowledge_subject`/`knowledgeSubject` because a shared Machine Client identity cannot prove caller-to-Subject authorization. A trusted server-side integration may bind a stable `namespace` + `externalSubjectId` only after its domain authorization. The Search client adds the configured numeric Client Application ID and rejects a mismatched Client Application ID.",
)

# Architecture guard must catch local Knowledge embedding wording as well.
replace(
    "tests/unit/test_cognia_only_rag_architecture.py",
    '        "retired local Knowledge RAG",\n',
    '        "retired local Knowledge RAG",\n        "embedding service for Knowledge RAG and Memory",\n',
)
