# Centralized Configuration

`/MASTER.md` remains the project Single Source of Truth. This document explains how centralized runtime configuration is implemented.

## Runtime configuration contract

`/.env` is the **single canonical runtime configuration file** in this repository. All non-secret runtime values and all required configuration keys are declared there.

`domain/contracts/config.py` is not a second configuration source. It defines only the typed schema and validation rules used to load `/.env`; runtime defaults/operational values must not be embedded in Python.

There is no `/.env.example` template anymore.

Runtime mechanisms are:

- local development/test: edit/use the root `/.env` values for the target environment;
- CI: consume the tracked root `/.env` and override test-only values in the ephemeral CI workspace;
- Kubernetes/OpenShift: provide the same environment contract through ConfigMap/Secret or equivalent runtime injection;
- offline/container deployment: inject environment-specific values through the deployment platform while preserving the same key contract.

Python code must consume runtime configuration only through `domain.contracts.config.settings`.

## Configuration groups

| Group | Environment keys |
|---|---|
| Application | `APP_*`, `DEBUG`, `HOST`, `PORT` |
| PostgreSQL/Alembic | `DATABASE_*`, `ALEMBIC_DATABASE_URL` |
| LLM | `LLM_*` |
| Embeddings/pgvector | `EMBEDDING_*`, `PGVECTOR_*` |
| Knowledge governance | `KNOWLEDGE_*` |
| API/Security | `INTERNAL_API_*`, `API_RATE_LIMIT_PER_MINUTE`, `RATE_LIMIT_*`, `CORS_ORIGINS`, `APPROVAL_TTL_SECONDS` |
| MCP | `MCP_*` |
| Zabbix | `ZABBIX_*` |
| Elastic Agent Builder | `ELASTIC_*`, `ELASTICSEARCH_*` |
| Prometheus | `PROMETHEUS_*` |
| Kubernetes | `KUBERNETES_*` |
| VM/SSH server-side adapters | `SSH_*`, `VM_*` |
| OIDC | `OIDC_*` |
| Offline Registry | `OFFLINE_IMAGE_REGISTRY`, `IMAGE_PULL_POLICY` |

## Secrets policy

The tracked `/.env` contains only non-secret defaults and **empty secret placeholders**. Passwords, API keys, bearer tokens, private keys and production-only credentials must never be committed with real values.

For production, secret values must be injected by the target secret-management/deployment system as environment overrides. The configuration loader keeps the same key names, so no application-code change is required.

CI includes a guard that fails if known sensitive keys in the committed `.env` become non-empty.

## Kubernetes/OpenShift

The API Deployment may consume the same key contract through `envFrom`:

- `aiops-platform-config` for non-secret values;
- `aiops-platform-secrets` for credentials and tokens.

These runtime injections override the safe placeholders in the repository `.env`.

## Adding a new setting

1. Add the typed required field to `domain/contracts/config.py` without a runtime value/default.
2. Add the corresponding key/value or empty secret placeholder to `/.env`.
3. Consume it only through `settings.<KEY>`.
4. Update centralized configuration tests if needed.
5. Do not introduce direct `os.getenv()` calls or duplicate runtime defaults elsewhere in application code.
