# AIOps Platform

Governed AIOps control plane for Signal ingestion, durable Incident/Evidence/RCA workflows, Cognia-only governed Knowledge RAG, human approval, allowlisted execution through MCP, verification and audit.

The architecture contract is [`MASTER.md`](MASTER.md). Strict production acceptance criteria are in [`PRODUCTION_ACCEPTANCE.md`](PRODUCTION_ACCEPTANCE.md), the current acceptance report is [`FINAL_ACCEPTANCE_REPORT.md`](FINAL_ACCEPTANCE_REPORT.md), Cognia integration details are in [`docs/COGNIA_INTEGRATION.md`](docs/COGNIA_INTEGRATION.md), production operational guidance is in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), configuration is in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md), and the authenticated Operations Copilot is documented in [`docs/CHATBOT.md`](docs/CHATBOT.md).

## Knowledge architecture

**Cognia is the only Governed Knowledge RAG in development, test and production.** It owns Knowledge Base permission, Knowledge/Revision lifecycle, processing/activation, Scope, Search and optional Context Generation. AIOps consumes Cognia through a machine Client Application. There is no second Knowledge RAG, no provider switch and no fallback to PostgreSQL/pgvector when Cognia is unavailable.

PostgreSQL remains the platform persistence layer. pgvector is the semantic retrieval layer for **Operational Memory only**. Historical pre-Cognia Knowledge content may exist only in a non-RAG archive without an embedding/retrieval path; it is not addressable by `KnowledgeRAGService`. Live operational Evidence remains authoritative for the current Incident.

## Local clean startup

Prerequisites: Python 3.12, PostgreSQL 16 with pgvector, and the external MCP/provider services required for the workflow you want to exercise.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
# Edit only local values/secrets in the untracked .env.
python -m alembic -c database/migrations/alembic.ini upgrade head
python -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000
```

A clean checkout has a complete non-secret development configuration in `.env.example`, so imports do not depend on undocumented shell variables. Cognia connection/credential placeholders may remain empty for local code work that does not perform Knowledge retrieval; any attempted Knowledge RAG call then fails explicitly as Cognia misconfiguration/unavailability rather than switching to another RAG. `.env` is ignored by Git and Docker.

## Operations Copilot (`/chatbot`)

After the API is running, open `http://localhost:8000/chatbot`. The browser validates the existing AIOps API key through `/api/v1/chatbot/me` and keeps the key only in `sessionStorage`; it is never persisted in chat history or sent to the LLM. The chatbot supports multi-turn general guidance plus governed VM, Kubernetes and Zabbix reads. The LLM may select only the bounded semantic tool catalog and never receives a generic shell, SSH, kubectl, SQL or arbitrary HTTP capability.

Read requests stay behind the existing MCP boundaries. VM telemetry uses the registered `vm_telemetry` tool, Zabbix uses the allowlisted `ZabbixMCPClient`, and Kubernetes reads go through `KUBERNETES_MCP_URL`. A requested VM/Kubernetes mutation first creates a durable Action Proposal and ChatOps Incident. Only an authenticated principal with the existing high-risk approval and approved-execution permissions may confirm the exact proposal; confirmation is digest-bound, creates/consumes the durable Approval once, then invokes the existing `ExecutionService` and attempts independent read verification. A text reply such as `yes` is not execution authority.

Example API call:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <api-key>' \
  -d '{"message":"cpu vm01 چقدره؟"}' \
  http://localhost:8000/api/v1/chatbot/message
```

Apply migration head before using the chatbot because sessions, bounded history and mutation proposals are durable PostgreSQL state. Full API, RBAC, tool, confirmation and production-boundary documentation is in [`docs/CHATBOT.md`](docs/CHATBOT.md).

## Production contract

Do **not** deploy by copying the development template unchanged. The production image forces `APP_ENV=production`, and startup fails closed for unsafe configuration such as mock providers, wildcard CORS, insecure MCP, direct Control-Plane SSH/Kubernetes access, invalid authentication, migration drift, or missing/unsafe Cognia configuration.

Production Cognia configuration requires an approved HTTP/HTTPS base URL with TLS verification, Client Application `clientId/clientSecret`, and explicit Knowledge Base IDs. `COGNIA_CLIENT_APPLICATION_ID` is a separate numeric Scope identity when Client/ExternalSubject scoping is used; it is not derived from the authentication `clientId`. `COGNIA_CONTEXT_PROFILE_ID` is optional until a profile is provisioned.

Promotion sequence:

1. Build the approved Python 3.12 image from an approved offline wheelhouse/runtime base and pin the resulting image digest.
2. Require the repository container gate to pass: builder/runtime isolation, smoke, exact-rootfs validation, Trivy policy, CycloneDX SBOM, cosign signing-path verification and immutable Kubernetes rendering.
3. Sign and verify the actual OCI artifact in the approved internal registry according to the organization promotion policy.
4. Inject ConfigMap/Secret values; do not bake `.env` into the image. Cognia `clientSecret` belongs in the external secret store.
5. Rotate/verify all credentials, including any credential-like values that have ever appeared in repository history.
6. Ensure the default-deny network path permits only an approved HTTP/HTTP(S)/FQDN/proxy route to Cognia; do not add unrestricted Internet egress.
7. Run `deployment/kubernetes/migrate-job.yaml` using the exact image digest being promoted.
8. Require the migration job to succeed before rolling the API Deployment.
9. Wait for `/api/v1/health/ready` to return HTTP 200; Cognia readiness is part of the required Production dependency set because Cognia is the sole Knowledge RAG.
10. Scrape `/api/v1/metrics` and ship stdout plus `/var/log/aiops` JSON/text logs to the production log platform.
11. Run the production smoke/E2E checks in `docs/DEPLOYMENT.md` and the acceptance scenarios in `PRODUCTION_ACCEPTANCE.md` before enabling write execution.

## Safety boundaries

- Operational API routes use explicit RBAC permissions; health/liveness/readiness/metrics and static dashboard assets are intentionally unauthenticated.
- The `/chatbot` UI is static, but every chatbot API call authenticates through existing API-key/OIDC RBAC; the UI never grants authority by itself.
- Chatbot model output is untrusted intent data. Backend validation, RBAC, durable approval, MCP allowlists, execution binding and verification remain authoritative.
- Cognia RAG is auxiliary Knowledge, not Live Evidence, execution authority or an LLM response.
- Cognia Machine Access Tokens are opaque; the runtime does not decode or assume JWT semantics and does not invent a machine refresh-token flow.
- Cognia Search uses explicit KB IDs and preserves KB/Knowledge/Revision/Chunk traceability. `relevanceScore` is retrieval relevance, not probability that a fact is true.
- Cognia failure/forbidden/index-unavailable is kept distinct from a successful empty Search; no alternate Knowledge RAG exists to mask the failure.
- External Subject scope must be supplied explicitly and uses a configured Client Application identity; service/customer display names are not guessed into Subject identities.
- Agents cannot directly register arbitrary write tools. Writes cross `ExecutionService` and the Tool Registry.
- Durable approvals expire, are bound to the execution intent, and are atomically consumed before approval-gated writes.
- Governed writes require durable approval validation, exact execution binding and one-time approval consumption; caller-provided approval context is accepted only after the trusted Control-Plane approval path validates it.
- MCP is the canonical Control-Plane boundary for external **operational tools**. Cognia is a separate governed Knowledge API boundary.
- VM writes go through the VM MCP edge. The Control Plane does not open SSH sessions.
- Production VM MCP requires a non-root key-only SSH identity, strict known-host verification, and target/service allowlists.
- MCP write identity is separated from read identity, and MCP writes are not transport-retried automatically.
- HTTP/MCP/Audit data uses bounded recursive secret redaction.

## Tests and CI

The `quality` workflow runs with Python 3.12 and performs repository/config hygiene checks, dependency and high-severity static security audits, the full unit/integration/scenario/security suite, Cognia contract regression tests, clean PostgreSQL+pgvector migration acceptance, approval/correlation locking checks, forward migration from an older schema and downgrade/rebuild validation. pgvector acceptance is for Operational Memory only; the active PostgreSQL schema has no Knowledge vector retrieval path.

The `chatbot-acceptance` workflow independently provisions PostgreSQL/pgvector, upgrades a clean database to migration head, and runs the durable ChatOps/session/approval plus LLM-orchestration acceptance tests. Repository-level chatbot tests also enforce API-key/RBAC behavior, bounded semantic tools, prompt-injection fail-closed behavior, Kubernetes GET-only evidence access and frontend key handling. Real LLM/MCP targets remain environment acceptance, not CI claims.

Cognia repository tests cover opaque machine-token lifecycle, 401 re-authentication, explicit scoped Search, KB/Revision/Chunk traceability, typed `application/problem+json` failures, no alternate-RAG fallback, registration idempotency, scope anti-spoofing, optimistic Revision concurrency/no blind retry, machine approval boundary and Context sufficiency semantics. They do **not** replace real Cognia environment acceptance.

The `container-acceptance` workflow builds separate hardened runtime and wheelhouse-builder images, then builds the production image as a true multi-stage artifact. Only `/opt/venv` crosses from builder to runtime; `/opt/wheels` and `/build` are rejected from the final filesystem. The gate then runs a container smoke test, exports the exact merged runtime rootfs, blocks fixable HIGH/CRITICAL Trivy findings, emits a CycloneDX SBOM, proves a cosign sign/verify path, validates immutable Kubernetes digest rendering and uploads the supply-chain evidence.

A green repository gate is necessary but not sufficient for production promotion. The target environment must still prove the real Cognia HTTP/HTTPS/Application Client/KB grants/Scope/lifecycle and optional Context Profile, approved internal wheelhouse/base-image supply, real OCI registry signing/verification/promotion, enterprise identity, real MCP endpoints including VM/Kubernetes/Zabbix chatbot queries and mutations, HA/DR and the production-like acceptance scenarios in `PRODUCTION_ACCEPTANCE.md`.