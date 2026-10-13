# Incident Room: live, auditable analysis progress

## Operator experience
The Incident Room shows the exact active LangGraph stage, a compact history of
observed MCP/provider checks, each selected Agent's start/completion/failure,
a spinner only while an actual stage is active, and actual elapsed time.

- The bar represents completed **observed workflow milestones**, not a
  prediction of how long MCP/LLM operations will take.
- Six primary *analysis* milestones are context/evidence, triage, specialist
  agents, RCA, evaluator, and decision. Provider and individual Agent events
  do NOT artificially increment the primary percentage.
- A graph path ending early (for example, evaluator blocks unsafe execution)
  is shown as completed when that branch actually ends. A failed Node never
  gains completion credit.
- Approval is shown as a pause for the human, not an endlessly spinning Agent.
  After an approved remediation starts, execution/verification/memory use a
  separate observed progress bar. Elapsed investigation time stops when analysis
  or Approval reaches a durable end; the execution timer starts independently.
- ETA is intentionally NOT provided: a statistically valid prediction would
  require enough historical per-service/per-provider stage durations and
  calibration. Percentages based on seconds elapsed or invented provider
  durations would mislead users.

## Backend and transport
LangGraph Nodes are instrumented at begin, success, and failure. Evidence
Collector emits progress for attempted Zabbix, VM MCP, Elasticsearch,
Prometheus, Kubernetes and Cognia checks. Parallel Agent calls emit their own
bounded start/completion/failure events. The event payload contains no LLM
content, file logs, raw Evidence, SSH command, or secrets.

Progress is appended directly to the existing PostgreSQL audit event store in
an independent, small transaction. This lets other API workers observe the
progress while the original workflow waits for remote MCP/LLM responses.
Progress emission is best effort and time-bounded: the main workflow is not
blocked if the feed's separate write fails. Progress is observational only,
not a checkpoint or a source of Approval/Execution authority.

Endpoints (read:incident authorization):
- GET /api/v1/incidents/{incident_id}/progress
- GET /api/v1/incidents/{incident_id}/progress/stream

The stream is **SSE over fetch()** with same-origin credentials and the normal
X-API-Key request header. Native EventSource cannot provide this existing API
key header. The server sends an initial snapshot plus changes and heartbeat
comments; no page refresh, decision regeneration, or model invocation occurs.
Events are scoped by Incident ID in the SQL query, work across workers, and
survive browser reconnection.

The browser retains its last trustworthy state during outages, reconnects
with backoff, and falls back to the small read-only lifecycle endpoint only
when the live stream is unavailable. A change in durable checkpoint version
or actual Approval/Incident status prompts a **material** report reload;
ordinary stage updates never reset the operator's Approval checkbox.

## Security and verification
All presented names use a fixed allowlist and are HTML escaped. The observer
never changes a target, snapshot digest, runbook, approval, or execution step.
The complete underlying API still enforces permission and Approval checks.
Progress events MUST NOT become evidence for RCA.

Acceptance:
- tests/unit/test_incident_progress.py
- tests/unit/test_incident_command_room.py
- tests/unit/test_incident_analysis_live_status.py

A real multi-worker VM/MCP+Zabbix+LLM staging test is still required before
declaring the feature production-verified.
