# Zabbix Problem/Recovery lifecycle

`aiops-platform` receives Zabbix lifecycle notifications through one authenticated endpoint:

```text
POST /api/v1/signals/zabbix
```

The same endpoint accepts both the original Problem and its Recovery. Zabbix MCP is not the push channel; MCP is used later by AIOps to collect live evidence after a signal has arrived.

## Recommended webhook body

Configure the Zabbix Action/Media Type so the problem event keeps a stable event identity and the recovery carries both identities:

```json
{
  "payload": {
    "eventid": "{EVENT.ID}",
    "recovery_eventid": "{EVENT.RECOVERY.ID}",
    "event_value": "{EVENT.VALUE}",
    "event_status": "{EVENT.STATUS}",
    "recovery_status": "{EVENT.RECOVERY.STATUS}",
    "name": "{EVENT.NAME}",
    "severity": "{EVENT.SEVERITY}",
    "hostid": "{HOST.ID}",
    "host": "{HOST.HOST}",
    "triggerid": "{TRIGGER.ID}",
    "tags": {EVENT.TAGSJSON},
    "operational_data": "{EVENT.OPDATA}",
    "acknowledged": "{EVENT.ACK.STATUS}",
    "timestamp": "{EVENT.TIMESTAMP}",
    "recovery_timestamp": "{EVENT.RECOVERY.TIMESTAMP}"
  }
}
```

Use the macro set supported by the installed Zabbix version. The application contract is the field names above; if a site uses a different Zabbix script, it may populate the same fields explicitly.

For deterministic VM remediation, the sender should additionally normalize operational identity fields when they are known authoritatively:

```json
{
  "service": "haproxy.service",
  "target_ip": "10.100.6.199",
  "target_port": 8800
}
```

These values are discovery inputs, not write authority. Before a restart plan is emitted, the platform must independently confirm the exact target/service through live VM MCP evidence. A generic tag such as `haproxyvm` is not interpreted as `haproxy.service`, and the trigger text is never parsed into a shell command, service name, or execution target.

## Identity rules

- Problem: `eventid` is the source event identity used for idempotency and incident correlation.
- Recovery: `recovery_eventid` is the recovery event identity and `eventid` remains the original problem identity for pairing.
- Alternative recovery senders may use `problem_eventid` plus `eventid` when `eventid` is the recovery identity.
- `value` is treated as arbitrary operational data and never determines lifecycle state.
- Only the explicit `event_value` field is interpreted as Zabbix event value (`1` problem, `0` recovery).
- `target_port` is accepted only as an explicit normalized integer. The platform does not derive a port from free-form trigger text.
- Knowledge/Cognia may guide read-only discovery, but a Knowledge-only identity cannot authorize a write.

This distinction is intentional because an alert may contain operational data equal to `0` while it is still a Problem.

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

A Recovery without a usable original Problem identity never creates a new Incident. The API accepts the notification but returns `recovery_unmatched=true` and a bounded terminal reason so the mapping/configuration problem is observable.

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
