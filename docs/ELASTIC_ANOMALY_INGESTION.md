# Elastic ML Anomaly Detection Ingestion

This integration separates **push-based detection** from **pull-based investigation**:

```text
Elastic ML Anomaly Detection
        |
Kibana Anomaly Detection Rule
        |
Webhook Connector (POST)
        v
/api/v1/signals/elasticsearch/anomaly
        |
normalize -> idempotency -> correlation -> Incident
        |
Signal-aware orchestration
        |
Elastic Agent Builder MCP / ES|QL
        v
logs around the anomaly timestamp + other operational evidence
```

The webhook is a trigger and lifecycle signal. It is intentionally not used to ship a large log bundle. After an active anomaly is accepted, the orchestrator performs read-only enrichment around the anomaly timestamp through the configured Elastic Agent Builder MCP endpoint.

## Kibana rule

Create an **Anomaly detection** rule for the ML job. Choose the result type appropriate to the job (bucket, record, or influencer) and configure the anomaly-score threshold. Elastic's default threshold is 75. Keep interim results disabled unless the operational use case explicitly needs provisional anomalies; AIOps also ignores interim results by default.

For service-specific jobs, make service identity deterministic using one of these mechanisms, in precedence order:

1. set the webhook field `service` explicitly;
2. include `service.name` (or `service`) among top influencers;
3. add a rule tag such as `service:payment-api`;
4. configure `ELASTIC_ANOMALY_JOB_SERVICE_MAP`.

## Webhook connector

Use the AIOps endpoint:

```text
POST https://<aiops-host>/api/v1/signals/elasticsearch/anomaly
Content-Type: application/json
X-API-Key: <AIOps INTERNAL_API_KEY>
```

Store the API key as a secret connector header. If Kibana restricts connector destinations with `xpack.actions.allowedHosts`, add the AIOps hostname. Configure TLS verification/CA on the Kibana connector according to the environment trust model.

Prefer **for each alert / on status change** so the stable `alert.uuid` lifecycle is available and repeated rule checks do not create notification noise.

### Active anomaly body

The payload intentionally uses Elastic rule/action variables rather than a custom Elasticsearch document shape:

```json
{
  "schema_version": "1.0",
  "source": "elastic",
  "event_type": "ml_anomaly",
  "state": "active",
  "scheduled_at": "{{date}}",
  "service": "",
  "rule": {
    "id": "{{rule.id}}",
    "name": "{{rule.name}}",
    "space_id": "{{rule.spaceId}}",
    "tags": "{{rule.tags}}",
    "url": "{{rule.url}}"
  },
  "alert": {
    "id": "{{alert.id}}",
    "uuid": "{{alert.uuid}}",
    "action_group": "{{alert.actionGroup}}",
    "action_group_name": "{{alert.actionGroupName}}"
  },
  "anomaly": {
    "score": "{{context.score}}",
    "timestamp_iso8601": "{{context.timestampIso8601}}",
    "is_interim": "{{context.isInterim}}",
    "job_ids": "{{context.jobIds}}",
    "message": "{{context.message}}",
    "anomaly_explorer_url": "{{context.anomalyExplorerUrl}}",
    "top_influencers": "{{context.topInfluencers}}",
    "top_records": "{{context.topRecords}}"
  }
}
```

The receiver accepts native arrays/objects and JSON-encoded Mustache values.

### Recovery body

Create a recovered action using the same connector and the same alert identity:

```json
{
  "schema_version": "1.0",
  "source": "elastic",
  "event_type": "ml_anomaly",
  "state": "recovered",
  "scheduled_at": "{{date}}",
  "service": "",
  "rule": {
    "id": "{{rule.id}}",
    "name": "{{rule.name}}",
    "space_id": "{{rule.spaceId}}",
    "tags": "{{rule.tags}}",
    "url": "{{rule.url}}"
  },
  "alert": {
    "id": "{{alert.id}}",
    "uuid": "{{alert.uuid}}",
    "action_group": "{{alert.actionGroup}}",
    "action_group_name": "{{alert.actionGroupName}}"
  },
  "anomaly": {
    "job_ids": "{{context.jobIds}}",
    "message": "{{context.message}}",
    "anomaly_explorer_url": "{{context.anomalyExplorerUrl}}"
  }
}
```

Recovery is idempotent. It attaches recovery Evidence to the original incident, cancels unconsumed approvals, and resolves a single-source incident. If other correlated sources are still active, the incident remains open for cross-source verification.

## Score and internal severity

The receiver maps Elastic's score bands into the platform vocabulary:

| Elastic score | Elastic UI band | AIOps severity |
|---:|---|---|
| 75-100 | critical | critical |
| 50-74.999 | major | high |
| 25-49.999 | minor | medium |
| 0-24.999 | warning | low |

The anomaly score remains preserved separately in `raw_data.anomaly.score`; severity mapping does not discard the original value.

## Runtime settings

```dotenv
ELASTIC_STACK_VERSION=9.3.2
ELASTICSEARCH_MCP_URL=https://<kibana>/api/agent_builder/mcp
ELASTICSEARCH_MCP_AUTH_HEADER=Bearer <token>
ELASTIC_AGENT_BUILDER_MCP_NAMESPACES=["platform.core"]
ELASTIC_AGENT_BUILDER_INDEX_PATTERN=logs-*

ELASTIC_ANOMALY_ACCEPT_INTERIM=False
ELASTIC_ANOMALY_CONTEXT_LOOKBACK_SECONDS=900
ELASTIC_ANOMALY_CONTEXT_LOOKAHEAD_SECONDS=300
ELASTIC_ANOMALY_JOB_SERVICE_MAP={"payment-latency-job":"payment-api"}
```

The active anomaly timestamp anchors an additional read-only Evidence window. With the defaults, AIOps asks the normal evidence collectors for 15 minutes before through 5 minutes after the anomaly time (capped at current time), then merges that evidence with the trigger and the current-time evidence set.

## Operational contract

- Stable alert IDs provide retry idempotency.
- Missing alert IDs fall back to a deterministic hash; no random ID is used for Elastic ML events.
- Cross-source correlation still uses the platform's conservative deterministic correlation policy.
- Unknown service identity is never guessed from arbitrary text. Use an explicit service, influencer/tag, or job map.
- Webhook authentication uses the existing API boundary and `ingest:signal` RBAC permission.
- The Agent Builder MCP path is read-only from the Control Plane and is used for context/investigation, not for webhook delivery.
- No database migration is required; anomaly/recovery metadata uses the existing Incident Evidence/context model.
