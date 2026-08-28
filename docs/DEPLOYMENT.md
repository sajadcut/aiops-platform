# Production Deployment Runbook

This runbook is the canonical operational path for promoting AIOps Platform. `MASTER.md` remains the architecture source of truth.

## Preconditions

A production rollout is prohibited until all of the following are true:

- feature-branch and merge CI are green;
- all production secrets are injected by the target secret manager and historical credential-like values have been rotated/verified;
- the promoted container image is built from the approved Python 3.12 base/wheelhouse, scanned, signed and pinned by immutable digest;
- PostgreSQL backup/restore is tested and a pre-migration recovery point exists;
- required Zabbix, Elastic and Prometheus MCP endpoints are reachable through HTTPS with the intended read identity;
- VM MCP, when enabled, uses a distinct write identity, strict known-host verification, non-root key-only SSH and target/service allowlists;
- OIDC issuer/audience/JWKS mapping and production RBAC identities have been validated in the target environment;
- production CORS origins are explicit;
- production LLM/embedding providers are real, reachable and have bounded timeouts;
- central log/metric collection is ready before writes are enabled.

## Configuration injection

Create `aiops-platform-config` from reviewed non-secret values and `aiops-platform-secrets` from the secret manager. Do not create either resource from a populated workstation `.env` file.

Mandatory safety examples:

```text
APP_ENV=production
DEBUG=false
DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP=true
PGVECTOR_VALIDATE_ON_STARTUP=true
MCP_REQUIRE_HTTPS=true
MCP_SERVER_REQUIRE_AUTH=true              # on internal MCP server deployments
CORS_ORIGINS=["https://<approved-ui-host>"]
LLM_PROVIDER=<real-provider>
EMBEDDING_PROVIDER=<real-provider>
SSH_ENABLED=false                         # Control Plane
```

If VM MCP is deployed, its isolated server configuration additionally needs `SSH_ENABLED=true`, a non-root `SSH_USERNAME`, `SSH_PRIVATE_KEY_PATH`, `SSH_KNOWN_HOSTS`, `SSH_STRICT_HOST_KEY_CHECKING=true`, non-empty `SSH_ALLOWED_TARGETS` / `SSH_ALLOWED_SERVICES`, and a distinct `MCP_WRITE_BEARER_TOKEN`.

## Database migration

Use the exact immutable image digest intended for the API rollout in both `deployment/kubernetes/migrate-job.yaml` and `deployment/kubernetes/aiops-platform.yaml`.

1. Take/verify a recoverable database backup or snapshot.
2. Apply the migration Job.
3. Require Job success. Do not begin the API rollout after a failed/partial migration.
4. Confirm `alembic_version` equals repository HEAD and pgvector validation passes.
5. Keep the migration Job logs with the release evidence.

The API performs a second fail-closed migration HEAD check at startup/readiness. Migrations must not be run independently by every replica.

## Rollout

1. Pin the Deployment image by signed digest, not mutable tag.
2. Apply configuration/secrets and the Deployment.
3. Wait for startup/liveness/readiness probes. `/api/v1/health/ready` must return HTTP 200; HTTP 503 means the pod is not production-ready.
4. Verify `/api/v1/metrics` is being scraped and `/var/log/aiops` plus stdout are being collected.
5. Confirm no production startup error indicates mock providers, wildcard CORS, insecure MCP, auth gaps or migration drift.
6. Keep write execution disabled at the traffic/policy layer until smoke tests pass.

## Production smoke tests

Use dedicated test identities and non-destructive targets.

- unauthenticated operational API request -> 401;
- viewer can read incidents/audit but cannot approve/execute;
- operator cannot approve high/critical risk;
- SRE can approve high-risk when the request is correctly bound;
- approval with altered target/action/tool/parameters/timeout/runbook/version/rollback -> 409;
- two concurrent consumers of one approval -> exactly one succeeds;
- consumed/expired/rejected approval cannot execute;
- dry-run performs no write and remains repeatable;
- MCP initialize -> initialized -> tools/list succeeds over TLS;
- MCP read token cannot call VM write tool;
- VM write token is distinct and an unallowlisted host/service is rejected;
- a controlled write traverses Approval -> Execution -> MCP -> VM and then independent verification;
- transaction logs contain request/correlation/execution/incident/approval/tool/action/target metadata without Authorization, API key, cookie, password, token, private key or DB credential values;
- dependency outage makes readiness/metrics/logs clearly indicate which dependency failed without exposing raw credentials/errors.

## Rollback and failure handling

Application rollback is allowed only when the previous image is compatible with the migrated schema. Never automatically downgrade the database as part of a pod rollback. If a migration itself requires rollback, use the release-specific database recovery plan and verified backup; Alembic downgrade support in CI is a correctness check, not authorization to destroy production data.

If a write returns an ambiguous downstream failure, do not automatically retry it. Determine whether the side effect occurred, use verification/read APIs, and create a new approval if another write is required.

If MCP/DB/LLM dependencies are unavailable, keep the system fail-closed for writes, preserve the incident/checkpoint/audit state, restore dependencies, and resume through the durable workflow rather than bypassing the execution boundary.

## Logging and incident trace

For each API/MCP transaction, retain structured JSON logs and human-readable rotated files. Correlate by `request_id`, `correlation_id`, `execution_id`, `incident_id` and `approval_id`. The desired operational trace is:

Signal -> Incident -> Evidence -> RCA -> Decision -> Approval -> Execution -> MCP Request -> MCP Response -> VM Action -> Verification -> Audit.

The HTTP/MCP transport logger records safe bounded JSON bodies. Uvicorn/FastAPI/std-library exceptions run through the same recursive redaction processor before console/text/JSON handlers.

## Post-deployment verification

- check replica readiness and restart count;
- confirm migration HEAD and pgvector dimension;
- confirm DB pool checked-out/overflow metrics remain below capacity;
- confirm latency/error-rate metrics and dependency gauges populate;
- confirm all configured MCP health checks succeed;
- execute one non-destructive Signal -> Incident workflow;
- execute one explicitly approved staging/canary write where policy permits;
- confirm verification and durable audit events are persisted;
- archive image digest, migration output, CI run IDs and smoke-test evidence with the release.
