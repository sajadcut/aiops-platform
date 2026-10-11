# Zabbix Team Guide v1.1 — authoritative Webhook contract

This page is synchronized to the 18-page **Zabbix_to_AIOps_Team_Guide_FA,
version 1.1 (2026-10-04)** supplied to the Zabbix integration team.
It defines the exact push-side contract for Problem and Recovery:

```http
POST https://<AIOPS-FQDN>/api/v1/signals/zabbix
Content-Type: application/json
X-API-Key: <AIOPS_API_KEY>
```

Zabbix uses a **Webhook Media Type** with a secret-text macro
`{$AIOPS_API_KEY}`. Its JS must send `JSON.stringify({payload: payload})`,
**not** the bare payload, with the API key only in the header.
AIOps requires an identity with `ingest:signal` permission. The API key
must not be embedded in the JSON body, logs or screenshots.

## Media Type parameter names (exact)

These keys are Webhook Media Type parameters. The JS strips unexpanded Zabbix
macros (`{...}`) and transfers their values to the JSON payload.

| Name | Zabbix macro |
|---|---|
| `url` | `https://<AIOPS-FQDN>/api/v1/signals/zabbix` |
| `api_key` | `{$AIOPS_API_KEY}` |
| `eventid` | `{EVENT.ID}` |
| `recovery_eventid` | `{EVENT.RECOVERY.ID}` |
| `event_value` | `{EVENT.VALUE}` |
| `event_status` | `{EVENT.STATUS}` |
| `name` | `{EVENT.NAME}` |
| `severity` | `{EVENT.SEVERITY}` |
| `hostid` | `{HOST.ID}` |
| `host` | `{HOST.HOST}` |
| `host_name` | `{HOST.NAME}` |
| `host_ip` | `{HOST.IP}` |
| `triggerid` | `{TRIGGER.ID}` |
| `trigger` | `{TRIGGER.NAME}` |
| `tags` | `{EVENT.TAGSJSON}` |
| `operational_data` | `{EVENT.OPDATA}` |
| `acknowledged` | `{EVENT.ACK.STATUS}` |
| `timestamp` | `{EVENT.TIMESTAMP}` |
| `recovery_timestamp` | `{EVENT.RECOVERY.TIMESTAMP}` |

`url` and `api_key` are transport configuration, **not JSON payload fields**.
Problem JSON includes a stable `eventid`. Recovery JSON includes both the
**original problem** `eventid` and the recovery `recovery_eventid`, and
`event_value=0`.

## Webhook request examples

```json
{
  "payload": {
    "eventid": "501001",
    "event_value": "1",
    "event_status": "PROBLEM",
    "name": "VM memory usage is high",
    "severity": "High",
    "hostid": "42",
    "host": "payment-vm-01",
    "host_name": "Payments VM",
    "host_ip": "10.20.10.99",
    "triggerid": "21001",
    "trigger": "VM memory usage is high",
    "tags": [
      {"tag":"platform","value":"vm"},
      {"tag":"asset_type","value":"vm"},
      {"tag":"service","value":"payment-api"},
      {"tag":"target_ip","value":"10.20.10.15"}
    ],
    "platform": "vm",
    "asset_type": "vm",
    "service": "payment-api",
    "target_ip": "10.20.10.15",
    "operational_data": "Memory utilization=94%",
    "acknowledged": "No",
    "timestamp": "1791712800"
  }
}
```

```json
{
  "payload": {
    "eventid": "501001",
    "recovery_eventid": "501009",
    "event_value": "0",
    "event_status": "RESOLVED",
    "name": "VM memory usage is high",
    "recovery_timestamp": "1791713100"
  }
}
```

## Identity contract and source normalization

Recognized **flat fields copied from EVENT.TAGSJSON**, as defined by the
guide's JS:

- Universal: `platform`, `asset_type`, `environment`, `service`,
  `business_service`, `owner`, `datacenter`, `correlation_key`.
- Kubernetes: `cluster`, `namespace`, `workload_kind`, `workload`,
  `pod`, `node`.
- VM: `target_ip` and numeric `target_port` (1–65535).
- Optional: `fqdn`, `endpoint`, `database`, `db_engine`,
  `db_instance`, `device`, `interface`.

AIOps additionally recognizes `filesystem` directly in the `tags` array
(the Disk alert example in Appendix A.2). The v1.1 JS does *not* copy
`filesystem` to a flat JSON field, so the receiver reads it from tags
without requiring a change to the delivered Media Type script.

All documented signal fields are preserved in Incident Evidence. AIOps uses
explicit flat identity first, then falls back to same-named event tags.
For missing or unresolved `eventid` the endpoint returns **422** instead
of inventing a random deduplication ID. Native and JSON-encoded tag arrays
are accepted. Timestamps accept Unix epoch seconds and ISO-8601; when
missing/invalid, processing time is the fallback rather than a fabricated
original-event timestamp.

Zabbix's `HOST.IP`/`host_ip`, `HOST.HOST`/`host`, and text within a
Trigger are **not** a VM MCP execution target. Only explicit `target_ip`
(or the identically named event tag) may bind the VM target. The optional
`target_port` is accepted only as an integer in the valid TCP range.
Zabbix never issues a direct restart, shell command or workload mutation.
The independent Approval/Execution/Verification gates remain authoritative.

Asset types tested against the guide's appendix:

| Guide case | `platform` / `asset_type` | Stable identity |
|---|---|---|
| VM Memory / Disk | `vm` / `vm` | `service` + `target_ip` |
| Network Down | `network` / `network` | `service` + `target_ip` or `endpoint` |
| Kubernetes CrashLoopBackOff | `kubernetes` / `kubernetes_workload` | `cluster` + `namespace` + `workload_kind` + `workload` + `service` |
| Cognia namespace memory | `kubernetes` / `kubernetes_namespace` | `cluster` + `namespace` |
| Database | `vm` / `database` | `service` + `db_instance` |
| Application/Web | `application` / `application` | `service` + optional `fqdn`/`endpoint` |

Kubernetes MCP evidence collection uses the event's explicit `namespace` for a
Kubernetes signal, rather than blindly selecting the AIOps process default.
This is a read-only scope; it does not authorize Kubernetes changes. Network
and Application alerts never promote an endpoint or HOST.IP into VM SSH
diagnostics. The Zabbix webhook route uses the existing configurable
high-volume rate limiter (default 500 requests/minute per client/route),
with the production PostgreSQL limiter and API-key authentication unchanged.

Pod names are optional, ephemeral investigation evidence, not stable workload
identity. The original `eventid` survives retry and Recovery. Problem retries
reuse the exact evidence reference; a matched Recovery is attached to the same
Incident and cannot create a new one.

## Full Zabbix Webhook delivery logging (AIOps side only)

For every **authenticated** Zabbix HTTP delivery, AIOps emits
`zabbix_webhook_received` at INFO level **before normalization and
validation**, including retries and incomplete event IDs. The structured
`raw_request.payload` is the complete original JSON payload delivered by
the unchanged v1.1 Webhook Media Type: event IDs, host/trigger metadata,
severity, operational data, all event tags, and any additional fields.
No arbitrary length cap from `LOG_HTTP_BODY_MAX_BYTES` is applied to this
specific log entry. Secret-bearing keys and secret-labeled tags have their
values redacted; the sender's original JSON is not modified.

A second entry captures the processing outcome:

- `zabbix_webhook_processed` — 2xx, Incident ID, Problem/Recovery state,
  deduplication/recovery status
- `zabbix_webhook_rejected` — invalid event identity or unmatched Recovery
  (including HTTP 422/503 and failure reason)
- `zabbix_webhook_failed` — unexpected processing/DB exception (HTTP 500)

All records include `log_type=zabbix_webhook`, `eventid`, and the
same request correlation trace ID as the HTTP transaction log.
No API key or Authorization header is added to the Zabbix payload log.
Large messages are limited only by the configured destination/rotation and
available storage, so plan disk capacity and log-retention policies.

With the default file logging settings (`LOG_LEVEL=INFO`,
`LOG_JSON_FILE_ENABLED=True`, `LOG_DIR=logs`,
`LOG_JSON_FILE=aiops.json.log`) on Windows, use PowerShell from the
repository root to inspect the complete records:

```powershell
Get-Content .\logs\aiops.json.log -Wait |
  Where-Object { $_ -match '"event": "zabbix_webhook_received"' }
```

For one source event ID including its receipt and outcome:

```powershell
Get-Content .\logs\aiops.json.log |
  ConvertFrom-Json |
  Where-Object { $_.log_type -eq "zabbix_webhook" -and $_.eventid -eq "501001" } |
  ConvertTo-Json -Depth 30
```

For Kubernetes deployments, the same JSON records go to configured
stdout/stderr logging collectors if JSON file logging is disabled. Normal
log rotation/retention still applies; logging is not a durable webhook queue.

## Zabbix action and acceptance

Configure Media Type **AIOps Signal Gateway**, User `aiops-webhook` (all
severity bands, all days, required Host Group read access), and an action
that forwards both **Problem operations** and **Recovery operations**.
Leave Update operations empty; ACK/comments are not new incidents in v1.1.

Acceptance requires: a 2xx Media Type test; a real Problem; a same-ID retry
with no duplicate Incident; matching recovery; a VM alert with `service`
and explicit `target_ip`; a Kubernetes alert with cluster/namespace/workload
identity; and confirmation that secrets never appear in logs/screenshots.
A green CI test is not a substitute for these real Zabbix/Kibana/network
delivery checks.

## Automatic governed remediation planning

A source-triggered Incident can reach remediation without a caller manually constructing an execution request. The deterministic planner is intentionally narrower than Agent reasoning:

1. Evaluator must first approve the evidence-grounded RCA for Decision.
2. A registered runbook must explicitly allow automatic planning for the fixed tool/action pair.
3. Live VM MCP `service_status` evidence must identify exactly one target/service and prove the service is inactive/failed.
4. Fresh `config_validate` evidence must be valid, or explicitly report that validation is unsupported.
5. Optional port identity comes only from matching live VM MCP port/TCP evidence.
6. The planner emits a typed `ssh_vm/restart_service` request bound to the runbook; Agent/LLM free text is never converted to a command.
7. Decision Engine still evaluates tool existence, risk, target verification and policy. VM restart remains high-risk and requires durable approval bound to the exact execution intent.
8. Immediately before execution, the same target/service/config preconditions are refreshed. If the service already recovered, evidence is unavailable, or configuration became unsafe, the write is blocked fail-closed.
9. After execution, success of the restart command is not sufficient. Fresh verification must demonstrate service health and, when the original port is known, listener/TCP recovery. Otherwise the Incident remains unresolved/escalated.

The runbook implementing this contract is `vm-service-recovery`. It does not make arbitrary service names or targets executable; those values must come from matching live evidence and are bound to the durable approval record before it is consumed once for execution.

## Recovery behavior

A matched Recovery:

1. is attached to the Incident that owns the original Zabbix problem event;
2. is persisted as new Zabbix Evidence using the recovery event ID;
3. is idempotent when Zabbix retries the same recovery webhook;
4. invalidates pending or already-approved-but-not-consumed execution approvals so a recovered service is not restarted by stale authority;
5. records `verification_source_recovery_received` in Audit/Incident Timeline;
6. marks a single-source Zabbix Incident `resolved` because the monitoring source has provided live recovery evidence;
7. does **not** auto-resolve when other correlated signals exist; the Incident remains active until cross-source verification is complete.

A Recovery without a usable original Problem identity never creates a new Incident. To prevent lost Recovery notifications, the HTTP endpoint returns **422** when recovery identity is incomplete, or **503** with `Retry-After: 10` when the original Problem has not yet been ingested. The unchanged v1.1 Zabbix Webhook script treats either non-2xx response as a failed delivery, allowing the team's configured Zabbix retries to handle out-of-order notifications. A matched Recovery and exact retries return 2xx.

## Response fields

The Zabbix ingestion response exposes lifecycle and remediation state, including:

```text
signal_state
recovered
recovery_unmatched
recovery_of_source_id
incident_status
approval_cancellations
remediation_plan
decision
approval
execution_result
verification_result
terminal_reason
```

Problem notifications continue through the normal Signal Gateway path: Knowledge RAG discovery, live MCP evidence, Triage, specialist Agents, RCA, Evaluator, deterministic Remediation Planner, Decision, governed Approval/Execution, Verification and Operational Memory.
