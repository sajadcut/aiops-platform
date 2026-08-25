# Centralized Configuration

`/MASTER.md` remains the project Single Source of Truth. This document only explains how its centralized-configuration requirement is implemented.

## Runtime configuration contract

All application runtime values come from environment variables. For local/dev/test execution the runtime loader reads the root `/.env` file. `/.env` is intentionally gitignored because it may contain secrets.

`/.env.example` is **only the complete safe template/schema for creating `.env`**. It mirrors every field accepted by `domain.contracts.config.Settings`, but it is not a second runtime configuration source.

Runtime mechanisms are:

- local development/test: copy `/.env.example` to `/.env`, then set environment-specific values in `.env`;
- CI: create an ignored `.env` from `/.env.example` during the workflow and override CI-specific values in that generated file;
- Kubernetes/OpenShift: provide the same environment keys through `aiops-platform-config` ConfigMap and `aiops-platform-secrets` Secret;
- offline/container deployment: inject the same environment contract through the deployment platform.

Python code must consume runtime configuration only through `domain.contracts.config.settings`. `config.py` defines types and validation only; it must not contain runtime values or operational defaults.

## Configuration groups

| Group | Environment keys |
|---|---|
| Application | `APP_*`, `DEBUG`, `HOST`, `PORT` |
| PostgreSQL/Alembic | `DATABASE_*`, `ALEMBIC_DATABASE_URL` |
| LLM | `LLM_*` |
| Embeddings/pgvector | `EMBEDDING_*`, `PGVECTOR_*` |
| Knowledge governance | `KNOWLEDGE_*` |
| API/Security | `INTERNAL_API_*`, `API_RATE_LIMIT_PER_MINUTE`, `RATE_LIMIT_*`, `CORS_ORIGINS`, `APPROVAL_TTL_SECONDS` |
| Zabbix | `ZABBIX_*` |
| Elasticsearch | `ELASTICSEARCH_*` |
| Prometheus | `PROMETHEUS_*` |
| VM/SSH | `SSH_*`, `VM_*` |
| OIDC | `OIDC_*` |
| Offline Registry | `OFFLINE_IMAGE_REGISTRY`, `IMAGE_PULL_POLICY` |

## Secrets policy

Passwords, tokens, API keys, private keys and private endpoint values must never be embedded in Python, YAML, Dockerfiles, runbooks or a committed `.env` file.

The repository stores empty secret placeholders only in `.env.example`. Real values belong in the ignored `.env` or the target platform secret store.

## Kubernetes/OpenShift

The API Deployment consumes configuration through `envFrom`:

- `aiops-platform-config` for non-secret environment values;
- `aiops-platform-secrets` for credentials and tokens.

`deployment/kubernetes/configuration.example.yaml` intentionally contains no duplicated values; the resources are generated from the same root environment contract.

## Adding a new setting

1. Add the typed required field to `domain/contracts/config.py` without a value/default.
2. Add the corresponding safe template key to `/.env.example`.
3. Consume it only through `settings.<KEY>`.
4. Update the centralized configuration tests if needed.
5. Do not introduce a direct `os.getenv()` or duplicate runtime value elsewhere in application code.
