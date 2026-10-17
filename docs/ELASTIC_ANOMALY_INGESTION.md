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
    "tags": {{rule.tags.asJSON}},
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
    "job_ids": {{context.jobIds.asJSON}},
    "message": "{{context.message}}",
    "anomaly_explorer_url": "{{context.anomalyExplorerUrl}}",
    "top_influencers": {{context.topInfluencers.asJSON}},
    "top_records": {{context.topRecords.asJSON}}
  }
}
```

Elastic renders array variables as comma-joined text when referenced directly. The webhook templates therefore use the documented `.asJSON` form for `rule.tags`, `context.jobIds`, `context.topInfluencers`, and `context.topRecords`. The receiver still accepts native arrays/objects and JSON-encoded legacy values.

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
    "tags": {{rule.tags.asJSON}},
    "url": "{{rule.url}}"
  },
  "alert": {
    "id": "{{alert.id}}",
    "uuid": "{{alert.uuid}}",
    "action_group": "{{alert.actionGroup}}",
    "action_group_name": "{{alert.actionGroupName}}"
  },
  "anomaly": {
    "job_ids": {{context.jobIds.asJSON}},
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
ELASTICSEARCH_MCP_PROTOCOL_VERSION=2024-11-05
# Choose exactly one authentication path:
# ELASTICSEARCH_MCP_AUTH_HEADER=ApiKey <elastic-api-key>
ELASTICSEARCH_MCP_AUTH_HEADER=
ELASTICSEARCH_MCP_USERNAME=<kibana-service-user>
ELASTICSEARCH_MCP_PASSWORD=<kibana-password>
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


## Generic Redis/threshold webhooks and read-only host discovery (October 2026)

The `/api/v1/signals/elasticsearch/anomaly` endpoint now distinguishes ML
anomaly notifications from rule/threshold events carrying `event.action`.
Both native and `{"payload":{...}}` forms are supported. Custom events keep
`service`, `severity`, `message`, `event.action` and
`event.correlation_key`; they are **not** fabricated as unknown ML jobs.
`/api/v1/signals/elasticsearch` remains the generic webhook endpoint.
A generic event ID like `query matched` is not a unique source ID; its
deterministic fingerprint also includes the event context and timestamp.

For Elasticsearch-originated incidents with a reported service, the ingestion
gateway queries the allowlisted Agent Builder ES|QL tool against bounded time
and fixed fields `service.name`, `service`,
`Properties.ServiceName.keyword`, `Properties.ServiceName`,
and `service.name.keyword`. It tolerates missing optional ECS projection
columns and caps returned rows. No LLM-generated query is executed.

Optional, independently validated aliases may be specified in `.env`:

```dotenv
ELASTIC_SERVICE_DISCOVERY_ALIASES={"gfpapi":["GFP_Backend"]}
```

The example does **not** assert that these are the same service in all
environments. An operator must verify that relationship first; omitting the
setting safely disables cross-label matching.

The discovery result is available from
`GET /api/v1/incidents/{incident_id}/host-discovery` and displayed in the
**Evidence & MCP** section of Incident Command Room. Result statuses distinguish
`no_matching_logs`, `no_host_metadata`, `candidates_found`,
`verified_by_vm_mcp` and `query_failed`.
A log's `host.name` or `host.ip` is merely a **candidate**, not a verified
VM destination or execution authorization. Only a sole candidate matching the
existing `SSH_ALLOWED_TARGETS` allowlist may receive a read-only
`service_status` VM MCP probe. Its returned service, target, loaded unit and
recognized systemd state must all match before the read can become durable
independent evidence. Every mutating action still requires separate signed
authorization, policy and Approval.

**Hostname-only Elastic logs:** if there is no valid `host.ip` but exactly one
candidate has `host.name`, AIOps attempts the same bounded, read-only
`service_status` call using the hostname itself. This is an SSH connection
initiated **only by the trusted VM MCP worker**, not directly by the API/LLM.
The exact hostname must be explicitly present in the VM MCP worker's
`SSH_ALLOWED_TARGETS` configuration (e.g.
`SSH_ALLOWED_TARGETS=["app01.internal.example","10.0.0.10"]`).
For production SSH, its hostname and key must also match the configured
`SSH_KNOWN_HOSTS`. The server must be resolvable **from the VM MCP worker**.
The API does not auto-resolve arbitrary log hostnames to bypass the allowlist.

The incident's `host-discovery` endpoint exposes the probe
`verification_method` (`ip` or `hostname`) and a coded
`verification_status` such as `candidate_hostname_not_allowlisted`,
`vm_read_failed`, or `verified_read_only`; the Persian Incident Room shows
the corresponding explanation. No result, mismatch, or SSH failure may grant
an execution target.

Sensitive ES|QL queries and result records stay excluded from HTTP/MCP logs;
the incident API exposes only bounded counts and host identity metadata.
A 200 response from Elastic MCP means tool transport succeeded, not that a
matching host or application-to-VM binding was established.

### Live acceptance (real environment required)

1. Send a non-ML nested Redis threshold alert and verify correct service,
   severity, message, signal type and per-occurrence identity.
2. Query the incident host-discovery API and check the actual query result
   count, candidate list and source labels (do not infer a match from HTTP 200).
3. If the source log label differs from the systemd unit, configure a
   validated alias. Search both before and after changing the alias.
4. Confirm one candidate in the VM allowlist yields only a read-only identity
   probe, and that a different service, two candidates or an unallowlisted
   target never grants a VM binding.
5. Confirm source event timestamps in the future do not move ES|QL search into
   the future. An empty result must not be presented as evidence of health.
6. Obtain human Approval separately before any actual service change.

### Deployment example: gfpapi logs in Kibana Space `mcp`

Kibana **Space** and MCP tool **namespace** are different identifiers.
The observed live MCP route is `/s/mcp/api/agent_builder/mcp`, with
`?namespace=platform.core`, which exposes `platform_core_execute_esql`.
Do **not** change the tool namespace to `mcp` merely because the Kibana
Space is called `mcp`.

For the gfpapi environment described by its operator, configure the actual
control-plane process environment (this is environment-specific; the generic
`.env.example` keeps the portable `logs-*` default):

```dotenv
ELASTICSEARCH_MCP_URL=http://10.248.34.169:5601/s/mcp/api/agent_builder/mcp
ELASTIC_AGENT_BUILDER_MCP_NAMESPACES=["platform.core"]
ELASTIC_AGENT_BUILDER_INDEX_PATTERN=1m-digitaloperation-gfpapi-*
# Enable ONLY once verified that the two log names refer to the same service:
# ELASTIC_SERVICE_DISCOVERY_ALIASES={"GFP_Backend":["gfpapi"]}
```

The index pattern is not hardcoded into the adapter, so deployments for
.NET, Java, Python, Kubernetes or unrelated applications can configure their
own real data view/index without changing source code.

After restarting the API, run the **read-only** integration check:

```bash
python -m scripts.check_elastic_integration --service GFP_Backend
```

This prints the *effective* index pattern and selected Kibana MCP namespace.
Incident Room also displays the effective index used by each fresh incident.
A service search returning zero records now performs a single bounded
`FROM <configured-index> | LIMIT 1` probe. When that probe finds rows but
the service/time search does not, the result is
`index_has_rows_no_service_time_match`, not a misleading generic
`no_matching_logs`. Nested ES|QL result formats are normalized; unparseable
response envelopes are labeled `response_format_unrecognized`.
The index-only probe never identifies or authorizes a host. Follow-up
`service_status` VM checks still require the existing allowlist and exact
verified service identity.
