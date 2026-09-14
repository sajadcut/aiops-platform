# AIOps Platform

Governed AIOps control plane for Signal ingestion, durable Incident/Evidence/RCA workflows, Cognia-backed governed Knowledge RAG, human approval, allowlisted execution through MCP, verification and audit.

The architecture contract is [`MASTER.md`](MASTER.md). Strict production acceptance criteria are in [`PRODUCTION_ACCEPTANCE.md`](PRODUCTION_ACCEPTANCE.md), the current acceptance report is [`FINAL_ACCEPTANCE_REPORT.md`](FINAL_ACCEPTANCE_REPORT.md), Cognia integration details are in [`docs/COGNIA_INTEGRATION.md`](docs/COGNIA_INTEGRATION.md), production operational guidance is in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), and configuration is in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Knowledge architecture

**Cognia is the canonical Governed Knowledge RAG for Production.** It owns Knowledge Base permission, Knowledge/Revision lifecycle, processing/activation, Scope, Search and optional Context Generation. AIOps consumes Cognia through a machine Client Application and never substitutes a hidden local Knowledge source when Cognia is unavailable.

PostgreSQL remains the platform persistence layer. pgvector is the semantic retrieval layer for **Operational Memory**. The local `knowledge_documents`/pgvector path remains only for deterministic development/test and migration compatibility; it is not the Production Knowledge system of record. Live operational Evidence remains authoritative for the current Incident.

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

A clean checkout has a complete non-secret development configuration in `.env.example`, so imports do not depend on undocumented shell variables. The development template uses local pgvector Knowledge so it does not require real Cognia credentials. Production validation rejects that provider and requires Cognia. `.env` is ignored by Git and Docker.

## Production contract

Do **not** deploy by copying the development template unchanged. The production image forces `APP_ENV=production`, and startup fails closed for unsafe configuration such as mock providers, wildcard CORS, insecure MCP, direct Control-Plane SSH/Kubernetes access, invalid authentication, migration drift, or a non-Cognia governed Knowledge provider.

Production Cognia configuration requires an approved HTTPS base URL with TLS verification, Client Application `clientId/clientSecret`, and explicit Knowledge Base IDs. `COGNIA_CLIENT_APPLICATION_ID` is a separate numeric Scope identity when Client/ExternalSubject scoping is used; it is not derived from the authentication `clientId`. `COGNIA_CONTEXT_PROFILE_ID` is optional until a profile is provisioned.

Promotion sequence:

1. Build the approved Python 3.12 image from an approved offline wheelhouse/runtime base and pin the resulting image digest.
2. Require the repository container gate to pass: builder/runtime isolation, smoke, exact-rootfs validation, Trivy policy, CycloneDX SBOM, cosign signing-path verification and immutable Kubernetes rendering.
3. Sign and verify the actual OCI artifact in the approved internal registry according to the organization promotion policy.
4. Inject ConfigMap/Secret values; do not bake `.env` into the image. Cognia `clientSecret` belongs in the external secret store.
5. Rotate/verify all credentials, including any credential-like values that have ever appeared in repository history.
6. Ensure the default-deny network path permits only an approved HTTPS/FQDN/proxy route to Cognia; do not add unrestricted Internet egress.
7. Run `deployment/kubernetes/migrate-job.yaml` using the exact image digest being promoted.
8. Require the migration job to succeed before rolling the API Deployment.
9. Wait for `/api/v1/health/ready` to return HTTP 200; when Cognia is the production provider, Cognia readiness is part of the required dependency set.
10. Scrape `/api/v1/metrics` and ship stdout plus `/var/log/aiops` JSON/text logs to the production log platform.
11. Run the production smoke/E2E checks in `docs/DEPLOYMENT.md` and the acceptance scenarios in `PRODUCTION_ACCEPTANCE.md` before enabling write execution.

## Safety boundaries

- Operational API routes use explicit RBAC permissions; health/liveness/readiness/metrics and static dashboard assets are intentionally unauthenticated.
- Cognia RAG is auxiliary Knowledge, not Live Evidence, execution authority or an LLM response.
- Cognia Machine Access Tokens are opaque; the runtime does not decode or assume JWT semantics and does not invent a machine refresh-token flow.
- Cognia Search uses explicit KB IDs and preserves KB/Knowledge/Revision/Chunk traceability. `relevanceScore` is retrieval relevance, not probability that a fact is true.
- Cognia failure/forbidden/index-unavailable is kept distinct from a successful empty Search; there is no hidden local pgvector fallback.
- External Subject scope must be supplied explicitly and uses a configured Client Application identity; service/customer display names are not guessed into Subject identities.
- Agents cannot directly register arbitrary write tools. Writes cross `ExecutionService` and the Tool Registry.
- Durable approvals expire, are bound to the execution intent, and are atomically consumed before approval-gated writes.
- Governed writes require a short-lived signed execution capability bound to the concrete incident/approval/tool/action/target/parameters/timeout/runbook/rollback intent; caller-provided `approval_granted` is not authorization.
- MCP is the canonical Control-Plane boundary for external **operational tools**. Cognia is a separate governed Knowledge API boundary.
- VM writes go through the VM MCP edge. The Control Plane does not open SSH sessions.
- Production VM MCP requires a non-root key-only SSH identity, strict known-host verification, and target/service allowlists.
- MCP write identity is separated from read identity, and MCP writes are not transport-retried automatically.
- HTTP/MCP/Audit data uses bounded recursive secret redaction.

## Tests and CI

The `quality` workflow runs with Python 3.12 and performs repository/config hygiene checks, dependency and high-severity static security audits, the full unit/integration/scenario/security suite, Cognia contract regression tests, clean PostgreSQL+pgvector migration acceptance, approval/correlation locking checks, forward migration from an older schema and downgrade/rebuild validation.

Cognia repository tests cover opaque machine-token lifecycle, 401 re-authentication, explicit scoped Search, KB/Revision/Chunk traceability, typed `application/problem+json` failures, no hidden fallback, registration idempotency, scope anti-spoofing, optimistic Revision concurrency/no blind retry, machine approval boundary and Context sufficiency semantics. They do **not** replace real Cognia environment acceptance.

The `container-acceptance` workflow builds separate hardened runtime and wheelhouse-builder images, then builds the production image as a true multi-stage artifact. Only `/opt/venv` crosses from builder to runtime; `/opt/wheels` and `/build` are rejected from the final filesystem. The gate then runs a container smoke test, exports the exact merged runtime rootfs, blocks fixable HIGH/CRITICAL Trivy findings, emits a CycloneDX SBOM, proves a cosign sign/verify path, validates immutable Kubernetes digest rendering and uploads the supply-chain evidence.

A green repository gate is necessary but not sufficient for production promotion. The target environment must still prove the real Cognia HTTPS/Application Client/KB grants/Scope/lifecycle and optional Context Profile, approved internal wheelhouse/base-image supply, real OCI registry signing/verification/promotion, enterprise identity, real MCP endpoints, HA/DR and the production-like acceptance scenarios in `PRODUCTION_ACCEPTANCE.md`.
