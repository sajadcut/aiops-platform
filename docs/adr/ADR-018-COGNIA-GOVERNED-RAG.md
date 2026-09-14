# ADR-018 — Cognia as the Only Governed Knowledge RAG

**Status:** ACCEPTED / COGNIA-ONLY; REAL ENV ACCEPTANCE REQUIRED

## Context

Cognia v1 provides the organization-managed Knowledge boundary: Application Client machine identity, Knowledge Base grants, immutable Knowledge/Revision lifecycle, processing/activation, Scope/External Subject isolation, Search over Current Active Revision chunks and Context Generation. Live operational Evidence remains the AIOps truth source and Operational Memory remains separate.

## Decision

1. Cognia is the only Governed Knowledge RAG for AIOps in development, test and production. PostgreSQL/pgvector is not a Knowledge retriever and no alternate RAG provider exists.
2. `KnowledgeRAGService` remains the internal AIOps abstraction so agents/workflows do not depend on raw Cognia HTTP shapes.
3. Backend integration uses Cognia Client Application Machine Authentication only. Human username/password credentials are forbidden in AIOps runtime.
4. Machine access tokens are opaque, cached only within returned `expiresIn`, and never decoded as JWTs. Machine auth has no refresh-token flow; expiry causes re-authentication with client credentials.
5. `clientId/clientSecret` are machine credentials. Numeric `clientApplicationId` is the Cognia Scope identity. They are separate values and must not be inferred from one another.
6. Search supplies explicit configured KB IDs and Cognia owns effective `kb.read`. Authorization is all-or-nothing; AIOps never silently removes an unauthorized KB.
7. Search consumes only Current Active Revision chunks. AIOps preserves KB/Knowledge/Revision/Chunk traceability. `relevanceScore` is retrieval relevance, not factual or operational confidence.
8. There is no fallback from Cognia to any alternate Knowledge RAG because no second RAG provider exists. Successful zero results are `empty`; provider/auth/index/dependency failures are separate typed states and are audit-visible.
9. Cognia outage does not make RAG an authority over Incident handling: reasoning may continue on fresh Live Evidence, but it must carry explicit Knowledge-provider degradation and may require human review according to downstream policy.
10. External Subject is accepted only from an explicit stable contract. AIOps does not infer Namespace/ExternalSubjectId from a service/customer display name. Machine scoped requests must match the configured numeric Client Application ID.
11. Context Generation is an auxiliary governed package, not a final LLM answer. `HTTP 200` with `isSufficient=false` remains insufficient context; `CONTEXT_INSUFFICIENT_KNOWLEDGE` remains an explicit provider error where the profile uses failGeneration.
12. Cognia authoring is explicit: registration uses a configured KB, explicit Scope and optional Idempotency-Key. Automatic transient retry is permitted only when Idempotency-Key makes registration replay-safe.
13. Candidate Revision always sends `expectedCurrentCandidateRevisionId`. A 409 concurrency conflict is not blindly retried; caller must re-read current state and make a new decision.
14. Machine Client does not automate human Approve/Reject decisions. AIOps does not emulate Cognia Knowledge delete because the consumer v1 contract does not expose it.
15. PostgreSQL remains AIOps platform persistence. pgvector remains the Operational Memory semantic retrieval layer.

## Security and deployment

- Cognia endpoints may use HTTP or HTTPS according to the deployed Cognia environment contract. When HTTPS is used in Production, certificate verification stays enabled.
- `COGNIA_CLIENT_SECRET` and access tokens are secrets and must be redacted from logs/audit/prompts and injected from the deployment secret store.
- KB IDs, Client Application ID and Context Profile ID are explicit configuration, never model-generated authority.
- Default-deny Kubernetes networking remains in force. If Cognia is external to the cluster, platform infrastructure must provide a narrowly allowlisted HTTPS/FQDN/proxy egress path; the application must not open broad `0.0.0.0/0` egress.
- Production readiness treats Cognia as required because it is the sole Knowledge RAG dependency.

## Acceptance

Repository tests must cover opaque-token lifecycle, re-auth, Search traceability, all-or-nothing request construction, no fallback, problem+json status/code handling, authoring idempotency, Scope anti-spoof, optimistic concurrency/no blind retry, Context sufficiency and secret/config fail-closed behavior.

Production PASS still requires real non-production Cognia evidence: the approved target HTTP/HTTPS endpoint, Application Client credential rotation, exact KB grants, positive/negative Search authorization, General/ClientApplication/ExternalSubject scope tests where used, registration → processing → Activated → Search, index/dependency outage behavior, and Context Profile/sufficiency tests if Context Generation is enabled.
