# Centralized Configuration

`/MASTER.md` remains the architecture Single Source of Truth. Runtime configuration is intentionally fail-closed and has one typed schema.

## Source-of-truth model

- `/.env.example` is the **tracked, non-secret configuration contract**. It contains every required key and safe development placeholders only.
- `/.env` is an **untracked local override**. It is ignored by Git and Docker build context.
- Deployment environment variables / ConfigMap / Secret values override both files.
- `domain/contracts/config.py` contains types and validation only; it must not contain operational defaults.
- Production images set `APP_ENV=production`, and production startup validation rejects unsafe combinations.

The loader reads `(.env.example, .env)` in that order. Native environment variables have the highest precedence. A clean checkout therefore imports deterministically for development, while production never depends on a developer PowerShell/session override.

## Required production rules

Production startup fails when any of these safety rules is violated:

- `DEBUG=true`;
- wildcard CORS;
- neither OIDC nor internal API-key authentication is configured;
- configured OIDC issuer/JWKS endpoints are not HTTPS;
- mock LLM or deterministic embedding provider is selected;
- placeholder database credentials are still in use;
- migration-head startup validation is disabled or the database is not at Alembic HEAD;
- required Zabbix, Elasticsearch or Prometheus MCP URLs are missing/non-HTTPS;
- `MCP_REQUIRE_HTTPS=false`;
- neither MCP bearer identity nor mTLS identity is configured;
- VM MCP is enabled without a distinct write bearer token;
- direct Control-Plane SSH or direct Control-Plane Kubernetes API access is enabled;
- approval, MCP, agent or A2A timeouts/limits are invalid.

The isolated VM MCP server additionally rejects production startup unless authentication is enabled, SSH host-key checking is strict, known-hosts and key path are configured, SSH user is non-root, and explicit target/service allowlists are non-empty.

## Configuration inventory

All fields below are required by `Settings`. “Secret” means the tracked template value must remain empty and production must inject it securely. “Prod required” means a production path needs a non-placeholder value; other fields may still be syntactically required but can intentionally be empty when that integration is disabled.

| Keys | Primary consumer | Secret | Production behavior / failure mode |
|---|---|---:|---|
| `APP_NAME`, `APP_VERSION` | API, health, MCP server identity | No | Required metadata; missing prevents settings load. |
| `APP_ENV` | production gates across API/MCP/SSH/knowledge | No | Must be `development`, `test`, or `production`; invalid prevents settings load. |
| `DEBUG` | FastAPI / SQLAlchemy | No | Must be false in production. |
| `HOST`, `PORT` | local/runtime launch tooling | No | Typed contract; deployment container currently binds `0.0.0.0:8000` explicitly, so changing these alone does not change the Kubernetes container command. |
| `DATABASE_URL` | async SQLAlchemy engine | Yes in production | Required; placeholder credentials are rejected in production; connectivity failure blocks readiness/startup checks. |
| `ALEMBIC_DATABASE_URL` | Alembic | Yes in production | Required for migration job/CLI; invalid URL makes migration fail. |
| `DATABASE_POOL_SIZE`, `DATABASE_MAX_OVERFLOW` | SQLAlchemy pool | No | Required; pool metrics are exposed. |
| `DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP` | API startup/readiness | No | Must be true in production; HEAD mismatch blocks startup/readiness. |
| `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_TIMEOUT_SECONDS` | LLM client/agents | `LLM_BASE_URL` No | `mock` is forbidden in production; downstream timeout/failure propagates as analysis failure/degradation. |
| `LLM_API_KEY` | LLM provider | Yes | Required when selected provider requires it; never log/commit. |
| `EMBEDDING_PROVIDER`, `EMBEDDING_BASE_URL`, `EMBEDDING_MODEL`, `EMBEDDING_DIMENSION`, `EMBEDDING_TIMEOUT_SECONDS` | embedding/RAG | No except provider-specific URL may be private | deterministic provider forbidden in production. |
| `EMBEDDING_API_KEY` | embedding provider | Yes | Inject if provider requires it. |
| `PGVECTOR_EXPECTED_DIMENSION`, `PGVECTOR_VALIDATE_ON_STARTUP` | vector startup validation | No | Production validation failure blocks startup when enabled. |
| `KNOWLEDGE_ALLOWED_SOURCE_TYPES`, `KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION` | knowledge/RAG governance | No | Empty/incorrect policy can reject governed knowledge or weaken expected source filtering. |
| `AGENT_LLM_TEMPERATURE`, `AGENT_MAX_TOKENS` | agent LLM calls | No | Required; invalid provider limits fail agent calls. |
| `AGENT_MAX_EVIDENCE_ITEMS`, `AGENT_MIN_EVIDENCE_ITEMS`, `AGENT_MIN_EVIDENCE_COVERAGE` | evidence gates | No | Bound evidence volume/quality; invalid production fractions fail startup validation where covered. |
| `AGENT_LOW_CONFIDENCE_THRESHOLD`, `AGENT_MIN_CONSENSUS_SCORE` | evaluator/decision gates | No | Must be in `[0,1]` in production. |
| `AGENT_SOURCE_QUALITY_WEIGHTS` | evidence scoring | No | Must be non-empty with values `[0,1]` in production. |
| `AGENT_MAX_RECOMMENDATIONS`, `AGENT_MAX_HYPOTHESES`, `AGENT_MAX_AUXILIARY_CONTEXT_ITEMS` | agent output bounds | No | Required runtime bounds. |
| `AGENT_ENABLED_AGENTS`, `AGENT_MAX_PARALLELISM` | orchestrator/coordinator | No | At least one enabled agent; parallelism must be positive in production. |
| `AGENT_MAX_EVIDENCE_ROUNDS`, `AGENT_MAX_DYNAMIC_EVIDENCE_TYPES` | iterative evidence collection | No | Must be positive in production. |
| `AGENT_INITIAL_EVIDENCE_WINDOW_SECONDS`, `AGENT_REFRESH_EVIDENCE_WINDOW_SECONDS`, `AGENT_STALE_EVIDENCE_SECONDS` | evidence freshness/windowing | No | Required; wrong values degrade RCA freshness. |
| `AGENT_TIMEOUT_SECONDS`, `AGENT_STRUCTURED_REPAIR_ATTEMPTS` | agent execution/repair | No | Timeout must be positive in production. |
| `AGENT_DISAGREEMENT_CONFIDENCE_FACTOR`, `AGENT_MISSING_EVIDENCE_CONFIDENCE_FACTOR`, `AGENT_CONFLICT_CONFIDENCE_PENALTY` | evaluator confidence | No | Fractions must be `[0,1]` in production. |
| `A2A_TIMEOUT_SECONDS`, `A2A_ALLOWED_TARGETS`, `A2A_REQUIRE_HTTPS` | agent-to-agent transport | No | Timeout positive; configured production targets require HTTPS. |
| `SIGNAL_CORRELATION_ENABLED`, `SIGNAL_CORRELATION_WINDOW_SECONDS`, `SIGNAL_CORRELATION_CANDIDATE_LIMIT` | Signal Gateway | No | Typed bounds prevent unbounded correlation lookup. |
| `LOG_LEVEL`, `LOG_CONSOLE_ENABLED`, `LOG_TEXT_FILE_ENABLED`, `LOG_JSON_FILE_ENABLED` | logging setup | No | At least one destination must be enabled or startup fails. |
| `LOG_DIR`, `LOG_TEXT_FILE`, `LOG_JSON_FILE` | rotating file logging | No | Target path must be writable; Kubernetes mounts `/var/log/aiops`. |
| `LOG_ROTATION_MODE`, `LOG_MAX_BYTES`, `LOG_BACKUP_COUNT`, `LOG_ROTATION_WHEN`, `LOG_ROTATION_INTERVAL`, `LOG_UTC` | file rotation | No | Invalid mode/levels fail settings validation. |
| `LOG_HTTP_BODY_ENABLED`, `LOG_HTTP_BODY_MAX_BYTES` | HTTP/MCP transaction logger | No | JSON bodies only; recursively redacted; oversized bodies are omitted with size metadata. |
| `INTERNAL_API_KEY` | API authentication | Yes | Optional only if OIDC is complete; one authentication mechanism is mandatory in production. |
| `INTERNAL_API_ROLE` | API-key RBAC mapping | No | Must map to a known policy when API key is used. |
| `API_RATE_LIMIT_PER_MINUTE`, `RATE_LIMIT_STRICT_REQUESTS`, `RATE_LIMIT_LOOSE_REQUESTS`, `RATE_LIMIT_WINDOW_SECONDS` | API rate limiter | No | Required; invalid values can deny or under-limit traffic. |
| `RETRY_MAX_ATTEMPTS`, `RETRY_DELAY_SECONDS`, `RETRY_BACKOFF_FACTOR` | retry helpers/MCP read transport | No | MCP writes deliberately do not auto-retry. |
| `CORS_ORIGINS` | FastAPI CORS | No | Wildcard forbidden in production. |
| `APPROVAL_TTL_SECONDS` | PostgreSQL approval store | No | Must be positive in production; expired approvals cannot transition/execute. |
| `MCP_PROTOCOL_VERSION`, `MCP_REQUIRE_HTTPS`, `MCP_TIMEOUT_SECONDS` | MCP clients/server | No | Production requires HTTPS; invalid timeout fails production validation. |
| `MCP_BEARER_TOKEN` | MCP read identity | Yes | Required unless mTLS identity is used for clients; required by authenticated internal server. |
| `MCP_WRITE_BEARER_TOKEN` | MCP write identity | Yes | Required for VM writes and must differ from read bearer in production. |
| `MCP_CA_CERT_PATH`, `MCP_CLIENT_CERT_PATH`, `MCP_CLIENT_KEY_PATH` | MCP TLS/mTLS | key path points to secret material | cert/key must be configured together; mounts are deployment responsibility. |
| `MCP_SERVER_PROVIDER`, `MCP_SERVER_REQUIRE_AUTH` | internal edge MCP server | No | Unsupported provider fails; auth must be true in production. |
| `ZABBIX_MCP_URL`, `ZABBIX_MCP_SERVER_NAME`, `ZABBIX_MCP_AUTH_HEADER` | Zabbix MCP client | auth header Yes | URL required/HTTPS in production. |
| `ELASTIC_STACK_VERSION`, `ELASTICSEARCH_MCP_URL`, `ELASTICSEARCH_MCP_AUTH_HEADER` | Elastic Agent Builder MCP | auth header Yes | Stack must be >=9.2; URL must be Agent Builder MCP path and HTTPS in production. |
| `ELASTIC_AGENT_BUILDER_MCP_NAMESPACES`, `ELASTIC_AGENT_BUILDER_INDEX_PATTERN` | Elastic evidence contract | No | namespaces must include `platform.core`. |
| `PROMETHEUS_MCP_URL`, `PROMETHEUS_MCP_SERVICE_LABEL`, `PROMETHEUS_MCP_AUTH_HEADER` | Prometheus MCP client | auth header Yes | URL required/HTTPS in production. |
| `KUBERNETES_MCP_URL`, `VM_MCP_URL` | governed external MCPs | No | If configured in production they must be HTTPS. VM MCP write token is mandatory. |
| `ZABBIX_URL`, `ZABBIX_USERNAME`, `ZABBIX_PASSWORD`, `ZABBIX_TIMEOUT_SECONDS` | edge/native Zabbix adapter | password Yes | Server-side helper; Control Plane should use MCP. |
| `ELASTICSEARCH_HOSTS`, `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_TIMEOUT_SECONDS` | edge/native Elasticsearch adapter | password Yes | Server-side helper; Control Plane should use MCP. |
| `PROMETHEUS_URL`, `PROMETHEUS_TIMEOUT_SECONDS` | edge/native Prometheus adapter | No | Server-side helper; Control Plane should use MCP. |
| `KUBERNETES_API_URL`, `KUBERNETES_TOKEN`, `KUBERNETES_TOKEN_FILE`, `KUBERNETES_CA_CERT_PATH`, `KUBERNETES_NAMESPACE`, `KUBERNETES_TIMEOUT_SECONDS`, `KUBERNETES_LOG_TAIL_LINES` | edge/native Kubernetes adapter | token Yes | Direct Control-Plane `KUBERNETES_API_URL` is forbidden in production. |
| `SSH_ENABLED`, `SSH_USERNAME`, `SSH_PRIVATE_KEY_PATH`, `SSH_KNOWN_HOSTS`, `SSH_STRICT_HOST_KEY_CHECKING`, `SSH_PORT`, `SSH_CONNECT_TIMEOUT` | isolated VM MCP SSH adapter | private key is external secret file | Production VM edge requires enabled, non-root user, key path, pinned known hosts and strict checking. Control Plane itself forbids direct SSH. |
| `SSH_ALLOWED_TARGETS`, `SSH_ALLOWED_SERVICES` | VM MCP authorization | No | Must be non-empty in production VM edge; syntactically valid but unlisted targets/services are rejected. |
| `VM_CPU_RECOVERY_THRESHOLD` | VM verification/recovery logic | No | Required threshold; API verification request may use its own bounded threshold. |
| `OIDC_ISSUER_URL`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL` | OIDC JWT validation | No | All-or-nothing effective configuration; issuer/JWKS must use HTTPS in production. |
| `OFFLINE_IMAGE_REGISTRY`, `IMAGE_PULL_POLICY` | offline deployment tooling/docs | No | Deployment metadata; application runtime does not select its own container image. Treat changes as deployment config, not API config. |

## Known configuration classifications

- **Secret:** API keys, bearer tokens, passwords, Kubernetes token, client/private-key material and database credentials are deployment secrets.
- **Unsafe development defaults:** `LLM_PROVIDER=mock`, `EMBEDDING_PROVIDER=deterministic`, wildcard CORS and HTTP MCP URLs are acceptable only because `APP_ENV=development`; production startup rejects them.
- **Server-side/edge-only legacy compatibility:** direct Zabbix/Elasticsearch/Prometheus/Kubernetes/SSH adapter settings exist for MCP server/provider migration and tests. Direct Control-Plane Kubernetes and SSH are explicitly production-blocked.
- **Deployment-only:** `OFFLINE_IMAGE_REGISTRY` and `IMAGE_PULL_POLICY` are not consumed by the running API and should not be mistaken for application runtime controls.

## Secrets policy

Real credentials must never be added to `.env.example`, `.env`, Docker layers, source, docs, logs, approvals, audit metadata or prompts. `.env` and `.env.*` are ignored by both Git and Docker; only `.env.example` is tracked. Request/MCP/file logs recursively redact authorization, API keys, tokens, passwords, cookies, credentials, DSNs and private-key material.

The repository history previously contained credential-like values. Removing `.env` from the current tree does **not** erase Git history. Those historical values must be treated as compromised until the owners confirm rotation; production promotion is blocked until that operational remediation is completed.

## Kubernetes / OpenShift

- `aiops-platform-config`: non-secret runtime values.
- `aiops-platform-secrets`: credentials/tokens/secret paths.
- `deployment/kubernetes/migrate-job.yaml`: run the exact promoted image and `alembic upgrade head` before Deployment rollout.
- `deployment/kubernetes/aiops-platform.yaml`: forces `APP_ENV=production`, migration validation, writable `/var/log/aiops`, readiness/liveness and metrics scraping.

## Adding a setting

1. Add a typed required field to `domain/contracts/config.py` without a Python runtime default.
2. Add the key to `.env.example` (empty if secret).
3. Consume it via `settings.<KEY>` only.
4. Add production validation when a dangerous value could become active.
5. Update this inventory and tests.
6. Do not introduce direct `os.getenv()` configuration paths or shell-only mandatory setup.
