# Prometheus Alertmanager Ingestion

The canonical Prometheus flow is push for detection and MCP for investigation:

```text
Prometheus metrics
      |
Prometheus alerting rules
      v
Alertmanager
      |
native webhook v4 (firing/resolved)
      v
POST /api/v1/signals/prometheus/alertmanager
      |
per-alert normalize / idempotency / correlation
      v
Incident
      |
trigger-time evidence window around startsAt
      v
Prometheus MCP range_query + Elastic/Zabbix/VM/Kubernetes evidence
      v
Triage / RCA / Decision / governed remediation
```

The generic Alertmanager webhook schema is accepted directly. No wrapper object and no custom Alertmanager payload template are required.

## Alertmanager receiver

Use the native webhook receiver and explicitly enable resolved notifications:

```yaml
route:
  receiver: aiops-platform

receivers:
  - name: aiops-platform
    webhook_configs:
      - url: https://<aiops-host>/api/v1/signals/prometheus/alertmanager
        send_resolved: true
        max_alerts: 0
        http_config:
          http_headers:
            X-API-Key:
              files:
                - /etc/alertmanager/secrets/aiops-api-key
          tls_config:
            ca_file: /etc/alertmanager/certs/aiops-ca.crt
            insecure_skip_verify: false
```

If the platform endpoint is intentionally plain HTTP inside a trusted internal network, omit `tls_config`. Do not place the real API key in Git; mount it from the deployment secret store.

`max_alerts: 0` avoids truncating the native webhook batch. If Alertmanager reports `truncatedAlerts > 0`, the receiver accepts the delivered alerts but marks the response as `partial=true` and logs the truncation.

## Prometheus rule requirements

Rules should carry a deterministic service label. The configured preferred label is:

```dotenv
PROMETHEUS_MCP_SERVICE_LABEL=service
```

Example:

```yaml
groups:
  - name: payment-api
    rules:
      - alert: HighErrorRate
        expr: |
          (
            sum(rate(http_requests_total{service="payment-api",status=~"5.."}[5m]))
            /
            sum(rate(http_requests_total{service="payment-api"}[5m]))
          ) > 0.05
        for: 2m
        labels:
          severity: critical
          service: payment-api
        annotations:
          summary: High HTTP 5xx rate
          description: More than 5% of payment-api requests are returning 5xx.
```

Service resolution order is the configured `PROMETHEUS_MCP_SERVICE_LABEL`, then `service`, `service_name`, `app`, `application`, and finally `job`.

## Native webhook contract

Alertmanager sends a v4 object containing group metadata and `alerts[]`. Each alert is processed independently using its own status:

```json
{
  "version": "4",
  "groupKey": "{}:{alertname=\"HighErrorRate\"}",
  "truncatedAlerts": 0,
  "status": "firing",
  "receiver": "aiops-platform",
  "groupLabels": {"alertname": "HighErrorRate"},
  "commonLabels": {
    "alertname": "HighErrorRate",
    "service": "payment-api",
    "severity": "critical"
  },
  "commonAnnotations": {
    "summary": "High HTTP 5xx rate"
  },
  "externalURL": "https://alertmanager.example",
  "alerts": [
    {
      "status": "firing",
      "labels": {
        "alertname": "HighErrorRate",
        "service": "payment-api",
        "severity": "critical"
      },
      "annotations": {
        "summary": "High HTTP 5xx rate"
      },
      "startsAt": "2026-09-19T08:10:00Z",
      "endsAt": "2026-09-19T08:20:00Z",
      "generatorURL": "https://prometheus.example/graph?...",
      "fingerprint": "abc123"
    }
  ]
}
```

## Lifecycle and idempotency

For a firing alert:

```text
fingerprint -> OperationalSignal.source_id
           -> retry-safe deduplication
           -> cross-source correlation
           -> Incident
```

If `fingerprint` is absent, the platform creates a deterministic hash from labels + `startsAt`; it never uses a random ID for the native Alertmanager path.

For a resolved alert:

```text
same fingerprint
      |
find original Incident
      |
attach recovery Evidence
      |
cancel unconsumed approvals
      |
other correlated active signals?
   /                 \
 no                  yes
 |                    |
resolve Incident   keep Incident open
                  for cross-source verification
```

Repeated resolved webhooks are idempotent using a recovery reference derived from fingerprint + `endsAt`.

## Trigger-time investigation

Alertmanager delivery can occur after the alert first starts. The platform therefore anchors a second evidence window to the alert's `startsAt` value:

```dotenv
PROMETHEUS_ALERT_CONTEXT_LOOKBACK_SECONDS=900
PROMETHEUS_ALERT_CONTEXT_LOOKAHEAD_SECONDS=300
```

With the default settings, the orchestrator collects read-only operational evidence from 15 minutes before through 5 minutes after `startsAt` (future end times are capped at current time). This collection uses the existing source adapters, including Prometheus MCP `range_query`, Elastic Agent Builder MCP, Zabbix MCP and available VM/Kubernetes evidence.

## Operational notes

- Keep `send_resolved: true`; otherwise the platform cannot receive authoritative Alertmanager recovery notifications.
- Keep a meaningful service label on every operational alert rule.
- Use `fingerprint` as the retry identity, not notification group key.
- A group can contain both firing and resolved alert objects; the platform evaluates `alerts[].status` individually.
- The legacy `POST /api/v1/signals/prometheus` wrapped payload endpoint remains for compatibility. New Alertmanager integrations should use `/api/v1/signals/prometheus/alertmanager`.
- Prometheus MCP remains a read-only investigation boundary. It does not replace Alertmanager as the event trigger.
