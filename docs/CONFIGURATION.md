# Centralized Configuration

## Single source of truth

`/.env.example` is the canonical configuration contract for the application. It contains every runtime key and is the only file that should be consulted to discover configuration names.

Runtime values are supplied through one of these mechanisms:

- local development: `.env` (never committed)
- Kubernetes: `aiops-platform-config` ConfigMap + `aiops-platform-secrets` Secret
- offline/container deployment: environment variables injected by the deployment platform

Python code must read configuration only through `domain.contracts.config.settings`.

## Configuration groups

| Group | Canonical keys |
|---|---|
| Application | `APP_*`, `DEBUG`, `HOST`, `PORT` |
| PostgreSQL | `DATABASE_*` |
| LLM | `LLM_*` |
| API/Security | `INTERNAL_API_KEY`, `API_RATE_LIMIT_PER_MINUTE`, `CORS_ORIGINS` |
| Zabbix | `ZABBIX_*` |
| Elasticsearch | `ELASTICSEARCH_*` |
| Prometheus | `PROMETHEUS_*` |
| OIDC | `OIDC_*` |
| pgvector | `PGVECTOR_*` |
| Offline Registry | `OFFLINE_IMAGE_REGISTRY`, `IMAGE_PULL_POLICY` |

## Secrets policy

Passwords, API keys, OIDC credentials and private endpoints must never be embedded in Python, YAML, Dockerfiles, runbooks or committed `.env` files.

The repository intentionally contains only empty placeholders in `.env.example`. Production values are injected at runtime.

## Kubernetes

The API Deployment consumes configuration only through `envFrom`:

- `aiops-platform-config` for non-secret configuration
- `aiops-platform-secrets` for credentials and tokens

See `deployment/kubernetes/configuration.example.yaml` for the expected resource names.

## Adding a new setting

1. Add the key once to `domain/contracts/config.py`.
2. Add the same key to `/.env.example`.
3. Consume it through `settings.<KEY>`.
4. Add/update the relevant configuration test.
5. Do not add the same value to another code/deployment file.
