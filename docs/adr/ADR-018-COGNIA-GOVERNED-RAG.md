# ADR-018 — Cognia as the Governed Production Knowledge RAG Provider

**Status:** ACCEPTED FOR INTEGRATION / REQUIRES REAL ENV ACCEPTANCE

## Context

The original MVP Knowledge RAG implementation stores governed documents and embeddings in PostgreSQL + pgvector. The project also deliberately keeps Operational Memory separate from Knowledge RAG and treats live operational Evidence as the source of truth.

The organization-provided Cognia v1 consumer contract introduces an external governed Knowledge platform with Application Client identity, explicit Knowledge Base permissions, immutable Revisions, Active/Candidate lifecycle, Search over active Chunk results, Scope/External Subject isolation and Context Generation.

## Decision

1. `KnowledgeRAGService` remains the AIOps abstraction. Callers do not depend directly on Cognia HTTP shapes.
2. `local_pgvector` remains the development/test and historical MVP Knowledge provider.
3. When production Knowledge governance is required, `KNOWLEDGE_PROVIDER=cognia` is mandatory. There is no hidden fallback from Cognia to local pgvector.
4. Operational Memory remains PostgreSQL + pgvector. Cognia does not replace incident-memory persistence.
5. Cognia access uses Application Client Machine Authentication only. Human username/password credentials are forbidden in the AIOps service.
6. Cognia access tokens are opaque. The integration caches them only according to the returned `expiresIn`; it never decodes or assumes JWT semantics.
7. Search always supplies an explicit configured Knowledge Base ID list. Cognia remains authoritative for effective `kb.read`, Scope and Client Application isolation.
8. A Cognia Search result is modeled as a traceable Chunk reference: Knowledge Base, Knowledge, Revision, Revision Number and Chunk ID are preserved. `relevanceScore` is retrieval relevance only and must not be used as factual confidence or operational Evidence confidence.
9. Search dependency/index failures remain explicit provider failures. AIOps does not convert them into an empty successful Knowledge result and does not query local Knowledge as a fallback.
10. Cognia Context Generation is exposed as an optional provider capability. Its Context Package is auxiliary material for a downstream Agent/LLM; it is not itself the final answer and `HTTP 200` with `isSufficient=false` remains an insufficient Context result.
11. The legacy `add_document()` path is not reused for Cognia authoring because it lacks mandatory governed inputs such as explicit Knowledge Base, Scope and Idempotency semantics. Any future Cognia authoring integration must implement the Cognia registration/revision contract explicitly rather than infer these values.
12. Cognia consumer V1 does not expose Knowledge delete; the AIOps Cognia provider therefore must not emulate delete through another channel.

## Production security boundary

- Environment-specific Cognia base URL must use HTTPS.
- TLS verification must remain enabled.
- `clientSecret` and access tokens are secrets and must not enter source, logs, audit metadata, prompts or committed manifests.
- Explicit Cognia KB IDs are configuration, not model-generated values.
- Cognia RAG remains auxiliary. It cannot authorize remediation, override Policy/Approval, or replace fresh operational Evidence.
- Cognia is not routed through the operational MCP boundary: it is a governed Knowledge service, not an operational tool/control-plane actuator. Its own Machine Authentication and KB/Scope authorization remain authoritative.

## Failure semantics

- Cognia transport or documented Search availability failures are surfaced as Knowledge-provider unavailability.
- Invalid upstream response shapes are surfaced as provider contract errors.
- Authentication/authorization failures of the AIOps Application Client are treated as integration/provider failures, not as the end user's AIOps authentication result.
- Incident analysis may continue using live Evidence when auxiliary Knowledge is unavailable, but it must not silently substitute a different Knowledge provider.

## Acceptance required before Production PASS

Repository tests can prove request/response mapping, opaque token behavior, typed failures, no-fallback behavior and traceability mapping. Production acceptance still requires a real non-production Cognia Application Client, real KB grants, HTTPS endpoint, Search against assigned KBs, Scope/External Subject tests, unavailable-index/dependency behavior, Context Generation (if used), credential rotation and observability evidence.

Until that real integration evidence exists, Cognia integration is **implemented but not production-proven**.
