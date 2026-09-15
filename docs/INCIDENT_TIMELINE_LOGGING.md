# Incident Timeline Logging

AIOps writes operational progress to two independent files through the same structured logging pipeline:

- `LOG_TEXT_FILE` (default `aiops.log`): human-readable operational log.
- `LOG_JSON_FILE` (default `aiops.json.log`): JSON Lines; one JSON object per line for machine parsing.

Both files receive the same canonical `workflow_step` event. The JSON file is JSONL even though its default filename ends in `.json.log`.

## Canonical event

Every workflow timeline event contains these fields:

- `event=workflow_step`
- `log_type=incident_timeline`
- `incident_id` when an Incident identity is available
- `stage`
- `component`
- `action`
- `status`
- optional `summary`
- optional structured `details`
- normal logger fields such as timestamp, level and logger name

The timeline is intentionally metadata-oriented. It records what the system did and the outcome without persisting raw secrets or unrestricted external payloads.

## Covered stages

The governed workflow emits timeline events for the following stages when they are reached:

1. `context_evidence`: trigger/context loading, asset/evidence merging and evidence refresh rounds.
2. `knowledge_rag` / `signal_asset_discovery`: Cognia Search and Context lifecycle (started/completed/failed/skipped).
3. `live_evidence`: MCP read calls to Zabbix, Elasticsearch, Prometheus, Kubernetes, VM and other read providers.
4. `triage`: triage result and routing.
5. `specialist_agents`: specialist analysis, handoffs and additional evidence rounds.
6. `llm` or a caller-supplied stage such as `rca`: model request started/completed/failed with provider/model/usage metadata.
7. `rca`: RCA synthesis completion.
8. `evaluator`: evaluation gate outcome or block.
9. `decision`: deterministic decision/policy outcome.
10. `approval`: approval requested/approved/rejected.
11. `execution`: governed MCP/tool execution and execution result.
12. `verification`: fresh post-action verification outcome.
13. `memory`: Operational Memory write-back outcome.
14. `governance`: other audited governance events that do not map to a narrower stage.

Stages are event-driven: a stage that is not reached is not falsely logged as completed.

## LLM logging

LLM timeline events deliberately do **not** contain the prompt, system prompt, API key, Authorization header or raw response. Safe metadata includes model, request ID, message count, input/output character counts, max tokens, temperature, thinking/reasoning settings, tool count, finish reason, usage and duration.

Typical sequence:

```text
stage=triage component=dotin-general-chatbot action=chat_completion_started status=started
stage=triage component=dotin-general-chatbot action=chat_completion_completed status=completed
```

When callers do not supply a workflow stage, the generic stage is `llm`.

## Cognia RAG logging

Cognia timeline events record Search/Context lifecycle, result counts, source IDs and relevance metadata. Raw query text and retrieved chunk content are not written into the canonical timeline event.

Typical sequence:

```text
stage=knowledge_rag component=cognia_rag action=search_started status=started
stage=knowledge_rag component=cognia_rag action=search_completed status=completed
```

A failed Cognia query is explicit as `search_failed`; it is never represented as a successful empty result.

## MCP logging

Every governed MCP HTTP call emits lifecycle events. Read tools use `stage=live_evidence`; write tools use `stage=execution`. The component is `mcp:<server-name>`. Writes retain the existing no-auto-retry rule.

Typical read sequence:

```text
stage=live_evidence component=mcp:zabbix action=<tool> status=started
stage=live_evidence component=mcp:zabbix action=<tool> status=completed
```

A transport/HTTP failure is `failed`; retryable read failures are `retrying`; authorization-policy failures are `blocked`.

## Approval and governed workflow events

`AuditService.record()` mirrors governed audit events into the dual-file timeline. This covers context, triage, specialist analysis, RCA, evaluator, decision, execution, verification and memory events already emitted by the orchestrator. ApprovalService additionally emits `approval_requested`, `approval_approved` and `approval_rejected` so the human gate is visible even before execution resumes.

## Secret handling

The canonical timeline must never intentionally contain:

- bearer/API tokens or Authorization headers
- passwords, client secrets or credentials
- private keys
- database DSN credentials
- raw LLM prompts/system prompts
- unrestricted raw external payloads

All timeline events pass through the same recursive redaction processor used by normal application logging. Sensitive-key and Bearer/Basic patterns are redacted in both text and JSON outputs. Boundary-specific timeline events also use bounded metadata rather than raw bodies.

## Example JSONL record

```json
{"event":"workflow_step","log_type":"incident_timeline","incident_id":"inc-456","stage":"knowledge_rag","component":"cognia_rag","action":"search_completed","status":"completed","summary":"Cognia Knowledge RAG returned 2 result(s)","details":{"result_count":2,"source_ids":["cognia:1:2:3:4"]}}
```

## Configuration

A typical configuration is:

```env
LOG_CONSOLE_ENABLED=True
LOG_TEXT_FILE_ENABLED=True
LOG_JSON_FILE_ENABLED=True
LOG_DIR=logs
LOG_TEXT_FILE=aiops.log
LOG_JSON_FILE=aiops.json.log
```

In Kubernetes/OpenShift the deployment mounts the configured log directory. File rotation continues to use the existing `LOG_ROTATION_*` settings.
