# AIOps Operations Copilot (`/chatbot`)

The Operations Copilot is a conversational control-plane interface for the existing AIOps platform. It does not create a second execution path. The LLM may classify intent, choose from a small semantic tool catalog, extract validated parameters and summarize evidence; authorization, MCP access, approval, execution and verification remain deterministic backend responsibilities.

## Trust boundary

```text
Browser / API client
  -> X-API-Key or OIDC/JWT
  -> FastAPI /api/v1/chatbot/*
  -> ChatbotService
       -> configured_llm_adapter()   [intent / explanation only]
       -> validated semantic tool
            -> read: governed MCP / low-risk ExecutionService
            -> write: Action Proposal
                      -> explicit decision endpoint
                      -> ChatOps Incident
                      -> durable Approval + intent digest
                      -> atomic approval consume
                      -> existing ExecutionService
                      -> VM/Kubernetes MCP
                      -> independent read verification
  -> PostgreSQL chat session/history/proposal + audit
```

The LLM never receives the API key, MCP credentials or bearer tokens. It never receives an arbitrary shell, SSH or kubectl capability. Tool output is treated as untrusted data, recursively redacted before it is returned or summarized, and bounded before it is placed in an LLM prompt.

## Web UI

Start the normal API service and open:

```text
http://<aiops-host>:8000/chatbot
```

The page first asks for the AIOps API key. The key is sent only as `X-API-Key` and is stored only in browser `sessionStorage` for the current tab session. It is never stored in `localStorage`, the chat database or the LLM conversation. Logout removes both the key and current session identifier from browser session storage.

The static UI is served from `dashboards/chatbot.html`, `chatbot.css` and `chatbot.js`; no additional frontend framework is required.

## API

All chatbot API routes require the existing `read:incident` permission at minimum.

### Validate identity

```bash
curl -sS \
  -H 'X-API-Key: <api-key>' \
  http://localhost:8000/api/v1/chatbot/me
```

### Send a message

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <api-key>' \
  -d '{"message":"cpu vm01 چقدره؟"}' \
  http://localhost:8000/api/v1/chatbot/message
```

Reuse the returned `session_id` for multi-turn conversation:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <api-key>' \
  -d '{"session_id":"<uuid>","message":"وضعیت RAM و disk همین VM رو هم بگو"}' \
  http://localhost:8000/api/v1/chatbot/message
```

### History

```bash
curl -sS \
  -H 'X-API-Key: <api-key>' \
  http://localhost:8000/api/v1/chatbot/sessions/<session-id>/history
```

A principal can read only sessions owned by the same authenticated subject. Unknown and foreign sessions both return `chat_session_not_found`.

### Confirm or reject a mutation

A write request first returns `kind=action_proposal` and a `proposal_id`. Confirmation is a separate backend operation:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <api-key>' \
  -d '{"confirm":true}' \
  http://localhost:8000/api/v1/chatbot/actions/<proposal-id>/decision
```

Reject with `{"confirm":false}`. A plain text message such as `yes` never authorizes execution.

## Semantic tool catalog

The LLM can select only the following semantic tools:

| Semantic tool | Backend boundary | Purpose | Mutation |
|---|---|---|---|
| `vm_metrics` | `vm_telemetry` -> VM MCP | CPU/memory/swap/load/IO | No |
| `vm_diagnostics` | `vm_telemetry` -> VM MCP | host/disk/network/process/system logs | No |
| `vm_service_status` | `vm_telemetry` -> VM MCP | systemd service status | No |
| `vm_service_logs` | `vm_telemetry` -> VM MCP | bounded service journal | No |
| `zabbix_problems` | `ZabbixMCPClient` | current/recent Zabbix problems | No |
| `kubernetes_read` | Kubernetes MCP | pod/deployment/events/usage/rollout/evidence | No |
| `vm_service_action` | Approval -> `ssh_vm` -> VM MCP | start/restart/reload service | Yes |
| `kubernetes_action` | Approval -> `kubernetes_mcp` | restart/rollback/scale workload | Yes |

The semantic catalog intentionally contains no shell, generic SSH, kubectl, arbitrary HTTP or raw SQL tool.

### Kubernetes read contract

The existing MCP tool name `collect_kubernetes_evidence` is retained. It accepts one allowlisted `operation` value rather than exposing arbitrary Kubernetes verbs:

- `list_pods`
- `pod_status`
- `deployment_status`
- `events`
- `resource_usage`
- `rollout_state`
- `service_evidence`

The server-side `KubernetesEvidenceClient` remains GET-only. In production the Control Plane still talks only to `KUBERNETES_MCP_URL`; `KUBERNETES_API_URL` on the Control Plane remains forbidden by production startup validation.

### Zabbix

The chatbot uses only the already-supported initMAX Zabbix MCP read contract. It does not invent a raw history/item metric tool. Current conversational Zabbix support therefore covers the allowlisted problem/alert evidence exposed by `ZabbixMCPClient`.

## Authorization

No broad `chat:execute` permission was introduced. The chatbot reuses existing granular RBAC:

- `viewer`: can authenticate and use read-only chatbot functions.
- `operator`: can use read-only chatbot functions and keeps the existing low-risk platform permissions, but cannot execute chatbot high-risk VM/Kubernetes mutations.
- `sre`: can use read-only functions and, because the existing role has both `approve:high_risk` and `execute:approved`, may confirm a chatbot high-risk proposal.

A future dedicated chatbot execution role can be added by changing the central RBAC policy; the chatbot must still require the underlying approval/execution permissions.

## Write flow and anti-replay

1. The LLM selects one mutation semantic tool and supplies arguments.
2. Backend validation normalizes target/service/namespace/replica/revision fields. Invalid or unknown tool calls fail closed.
3. The chatbot checks the authenticated identity's existing high-risk approval and execution permissions.
4. A durable ChatOps Incident is created. The platform does not bypass the existing `incident_id` requirement.
5. A durable Action Proposal is stored with an SHA-256 digest of the complete canonical execution intent.
6. No Approval exists yet and nothing is executed.
7. The user confirms the exact `proposal_id` through the decision endpoint.
8. The backend recomputes and compares the intent digest. Any parameter tampering fails before Approval creation.
9. The existing Approval metadata binding is created, approved by the authenticated subject, checked with `assert_bound`, then atomically moved to `consumed`.
10. The existing `ExecutionService` invokes the registered governed tool.
11. VM writes go through VM MCP; Kubernetes writes go through Kubernetes MCP.
12. A read-only post-action verification is attempted. Execution success and verification success are reported separately.
13. A confirmed proposal cannot be replayed; proposal state and consumed Approval both prevent a second execution.

## Persistence and retention

Migration `f3c4d5e6f7a8` creates:

- `chat_sessions`: subject ownership, role snapshot and 24-hour sliding expiry.
- `chat_messages`: bounded user/assistant/tool history.
- `chat_action_proposals`: exact mutation proposal, intent digest, expiry, Approval and execution outcome.

Conversation context is bounded to the most recent history and only a smaller recent slice is sent to the LLM. Raw provider payloads are not persisted as chat messages; tool rows contain completion/source metadata only. API keys and MCP/LLM secrets are never persisted in chat tables.

## Rate limits and bounds

- Chat message length: maximum 4,000 characters.
- Persisted message content: maximum 16,000 characters per row.
- Conversation history query: maximum 40 rows.
- LLM context: recent bounded messages only.
- LLM semantic tool calls: maximum 3 per user request.
- Mutation requests: exactly one mutation per request; mixed read/write batches are rejected.
- Action proposal TTL: 15 minutes.
- Session TTL: 24 hours sliding.
- Chat message and decision endpoints reuse the existing strict API rate limiter.
- Provider transport timeouts remain controlled by existing LLM/MCP settings.

## Observability and audit

The chatbot writes durable audit events for request, LLM failure, tool success/failure, policy block, action proposal, rejection, approval consumption and execution result. Correlation metadata includes session/proposal/incident/approval identifiers where applicable, but not prompt bodies or credentials.

Prometheus metrics include:

- `aiops_chatbot_requests_total`
- `aiops_chatbot_request_duration_seconds`
- `aiops_chatbot_llm_failures_total`
- `aiops_chatbot_tool_calls_total`
- `aiops_chatbot_blocked_actions_total`
- `aiops_chatbot_executed_actions_total`

They are exposed by the existing application metrics endpoint.

## Configuration

No chatbot-specific secret is introduced. Configure the existing platform contracts:

- `INTERNAL_API_KEY` / `INTERNAL_API_ROLE`, or production OIDC settings.
- `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`.
- `VM_MCP_URL` and fixed MCP Control-Plane identity for VM questions/actions.
- `KUBERNETES_MCP_URL` for Kubernetes questions/actions.
- `ZABBIX_MCP_URL` and its configured authentication header for Zabbix evidence.
- PostgreSQL `DATABASE_URL` with migration `f3c4d5e6f7a8` applied.

Production startup already rejects mock LLM, direct Control-Plane SSH/Kubernetes access and unsafe MCP identity configuration.

## Tests

The standard repository suite covers tool allowlisting, API-key authentication/RBAC, Kubernetes GET-only/MCP contract and frontend secret handling. `chatbot-acceptance.yml` provisions PostgreSQL/pgvector, upgrades to migration head and additionally proves durable session ownership, general LLM answer persistence, LLM failure handling, invalid model tool blocking, validated read dispatch, mutation proposal-without-execution, viewer mutation block, exact-intent tamper rejection, Approval consumption and replay prevention.

## Production acceptance boundary

The following require a real environment and must not be inferred from mocks/CI:

- live Dotin/OpenAI-compatible LLM gateway behavior and enterprise identity mapping;
- live initMAX/Zabbix MCP data;
- live VM MCP against approved VM targets and service allowlists;
- live Kubernetes MCP read permissions, Metrics API availability and namespace scoping;
- live Kubernetes/VM mutation plus independent verification;
- production TLS/network policy, secret manager delivery and real OIDC/JWKS behavior.

Mark these `REAL ENV REQUIRED` until exercised against staging/production-equivalent infrastructure.
