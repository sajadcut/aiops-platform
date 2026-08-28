# AIOps Platform

Governed AIOps control plane for Signal ingestion, durable Incident/Evidence/RCA workflows, human approval, allowlisted execution through MCP, verification and audit.

The architecture contract is [`MASTER.md`](MASTER.md). Production operational guidance is in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), configuration is in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md), and the latest production-readiness audit is in [`docs/PRODUCTION_READINESS_AUDIT_2026-08-28.md`](docs/PRODUCTION_READINESS_AUDIT_2026-08-28.md).

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

A clean checkout has a complete non-secret development configuration in `.env.example`, so imports do not depend on undocumented shell variables. `.env` is ignored by Git and Docker.

## Production contract

Do **not** deploy by copying the development template unchanged. The production image forces `APP_ENV=production`, and startup fails closed for unsafe configuration such as mock providers, wildcard CORS, insecure MCP, direct Control-Plane SSH/Kubernetes access, invalid authentication, or migration drift.

Promotion sequence:

1. Build the approved Python 3.12 image from an approved offline wheelhouse and pin/sign the resulting image digest.
2. Inject ConfigMap/Secret values; do not bake `.env` into the image.
3. Rotate/verify all credentials, including any credential-like values that have ever appeared in repository history.
4. Run `deployment/kubernetes/migrate-job.yaml` using the exact image digest being promoted.
5. Require the migration job to succeed before rolling the API Deployment.
6. Wait for `/api/v1/health/ready` to return HTTP 200; `not_ready` is HTTP 503.
7. Scrape `/api/v1/metrics` and ship stdout plus `/var/log/aiops` JSON/text logs to the production log platform.
8. Run the production smoke/E2E checks in `docs/DEPLOYMENT.md` before enabling write execution.

## Safety boundaries

- Operational API routes use explicit RBAC permissions; health/liveness/readiness/metrics and static dashboard assets are intentionally unauthenticated.
- Agents cannot directly register arbitrary write tools. Writes cross `ExecutionService` and the Tool Registry.
- Durable approvals expire, are bound to the complete execution intent, and are atomically consumed before writes.
- VM writes go through the VM MCP edge. The Control Plane does not open SSH sessions.
- Production VM MCP requires a non-root key-only SSH identity, strict known-host verification, and target/service allowlists.
- MCP write identity is separated from read identity, and MCP writes are not transport-retried automatically.
- HTTP/MCP transaction logs include correlation/request/execution metadata and bounded, recursively redacted JSON bodies.

## Tests and CI

The `quality` workflow runs on feature-branch pushes and pull requests with Python 3.12. It performs repository/config hygiene checks, dependency and high-severity static security audits, the full test suite, clean PostgreSQL+pgvector migration acceptance, approval locking/correlation checks, forward migration from an older schema and downgrade/rebuild validation.

The production offline image still depends on the organization's approved wheelhouse/image-signing pipeline. A successful source CI run is necessary but not sufficient for production promotion.
