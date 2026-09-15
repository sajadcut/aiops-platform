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

## Identity rules

- Problem: `eventid` is the source event identity used for idempotency and incident correlation.
- Recovery: `recovery_eventid` is the recovery event identity and `eventid` remains the original problem identity for pairing.
- Alternative recovery senders may use `problem_eventid` plus `eventid` when `eventid` is the recovery identity.
- `value` is treated as arbitrary operational data and never determines lifecycle state.
- Only the explicit `event_value` field is interpreted as Zabbix event value (`1` problem, `0` recovery).

This distinction is intentional because an alert may contain operational data equal to `0` while it is still a Problem.

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

The Zabbix ingestion response additionally exposes:

```text
signal_state
recovered
recovery_unmatched
recovery_of_source_id
incident_status
approval_cancellations
verification_result
```

Problem notifications continue through the normal Signal Gateway path: Knowledge RAG discovery, live MCP evidence, Triage, specialist Agents, RCA, Evaluator, Decision and governed remediation.
