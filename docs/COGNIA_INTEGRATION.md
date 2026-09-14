# Cognia Integration Contract for aiops-platform

Status: repository contract implemented; real environment acceptance required.

## Role in architecture

Cognia is the only Governed Knowledge RAG in aiops-platform across development, test and production. It owns Knowledge Base permissions, Knowledge/Revision lifecycle, processing/activation, Scope, Search and Context Profile policy. It is not Live Operational Evidence, an LLM, an execution tool or Operational Memory.

Operational Memory remains PostgreSQL + pgvector. Live Evidence remains authoritative for the current Incident. There is no alternate/local Knowledge RAG or Cognia fallback in any environment.

## Machine identity

AIOps uses a Cognia Client Application and `POST /api/access/client-auth/token`. The access token is opaque and is never decoded. Machine auth has no refresh token; the service re-authenticates after `expiresIn`. Creating the Client Application does not grant KB access; required KB grants are provisioned separately by Cognia administration.

Configuration separates:

- `COGNIA_CLIENT_ID` / `COGNIA_CLIENT_SECRET`: machine authentication credentials.
- `COGNIA_CLIENT_APPLICATION_ID`: numeric Client Application identity used by Scope/Search.
- `COGNIA_KNOWLEDGE_BASE_IDS`: exact KBs AIOps is allowed/configured to query.
- `COGNIA_CONTEXT_PROFILE_ID`: optional pre-provisioned Context Profile.

## Search

AIOps sends all configured KB IDs explicitly. Cognia authorization is all-or-nothing; the client does not drop unauthorized KBs. Search consumes Current Active Revision chunks only. The adapter preserves KB, Knowledge, Revision, Revision Number and Chunk IDs. `relevanceScore` is retrieval relevance and never becomes factual confidence or live Evidence confidence. The supplied Cognia contract does not define it as a normalized 0..1 probability, so the default incident path does not impose a client-side normalization threshold; any explicit threshold must be justified by accepted environment evidence.

Successful zero results are represented as `empty`. Authentication, permission, hidden/not-found, contract, index/dependency and transport failures remain separate typed provider status. They are not converted into empty results and do not trigger any alternate RAG fallback.

## Scope and External Subject

No Subject is inferred from an Incident service/customer name. A trusted upstream integration may provide `context.knowledge_subject` only as an explicit stable contract containing `namespace` and `externalSubjectId` (or the internal snake_case alias). The Search client adds the configured numeric Client Application ID and rejects a mismatched Client Application ID. Client ownership is not a substitute for caller-to-Subject authorization; deployments using sensitive ExternalSubject scopes must bind the upstream caller/incident to that Subject before forwarding it.

For Context Generation the request subject contains only `namespace` and `externalSubjectId`; the Client Application is defined by the Context Profile.

## Authoring and Revision

Registration calls `/api/engine/knowledge-bases/{kbId}/knowledge` with explicit KB and Scope. A caller should provide an `Idempotency-Key`; automatic transient retry is allowed only when that key is present. Registration creates Knowledge + Revision #1 atomically.

Content changes create a Candidate Revision rather than editing an old Revision. `expectedCurrentCandidateRevisionId` is always sent (nullable). `KNOWLEDGE_REVISION_CONCURRENCY_CONFLICT` is returned to the caller and is not blindly retried; current state must be read again first.

A machine Client Application does not perform human Approve/Reject decisions. Processing is observed until `Activated`; registration is not equivalent to Searchable. The v1 consumer contract has no Knowledge delete, so AIOps does not emulate one.

## Context Generation

Context Generation is used only when a Context Profile has been provisioned. The Context Package is auxiliary input for the downstream reasoning layer, not a final answer. `HTTP 200` with `isSufficient=false` is preserved as insufficient. A fail-generation profile may return `422 CONTEXT_INSUFFICIENT_KNOWLEDGE` without a package.

## Error and retry policy

External API failures are interpreted from HTTP status + Cognia `code`; human-readable title/detail are not control-flow inputs. Search/read requests may use bounded transient retry. Registration is retried only with Idempotency-Key. Candidate Revision creation is never blindly retried because optimistic concurrency requires a fresh read/decision after conflict.

## Deployment and acceptance

Production requires an approved HTTPS Cognia endpoint with TLS verification. Secrets come from the deployment secret store and are covered by recursive redaction. If Cognia is outside the Kubernetes namespace/cluster, infrastructure must provide a narrow allowlisted HTTPS/FQDN/proxy egress path; unrestricted Internet egress is not added to the application NetworkPolicy.

Before Cognia can be marked Production PASS, record evidence for: machine authentication and rotation, exact KB grants, positive and negative Search authorization, General/ClientApplication/ExternalSubject behavior where used, registration → approval (if policy requires human approval) → processing → Activated → Search, index/dependency outage behavior/no fallback, and Context Profile/sufficiency behavior if Context Generation is enabled.
