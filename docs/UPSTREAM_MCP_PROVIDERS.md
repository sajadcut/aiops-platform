# Upstream MCP Provider Contracts

The AIOps Control Plane treats MCP as the canonical external-tool boundary. For the three primary observability systems, adapters are aligned to the actual upstream projects below rather than to invented local tool names.

## Prometheus

Upstream: `prometheus/prometheus-mcp`.

Supported Control-Plane read tools: `query`, `range_query`, `list_alerts`, `metric_metadata`, `series`, `label_names`, `label_values`, `healthy`, `ready`.

AIOps metric collection maps canonical metric requests to `range_query` and builds a deterministic PromQL selector from `PROMETHEUS_MCP_SERVICE_LABEL`. Destructive/admin tools such as `delete_series`, `clean_tombstones`, `reload`, `quit` and `snapshot` are intentionally excluded from the Control-Plane allowlist.

Recommended deployment: run upstream Prometheus MCP with Streamable HTTP and restrict its registered tool set to the read-only capabilities required by AIOps.

## Zabbix

Upstream: `initMAX/zabbix-mcp-server`.

Supported Control-Plane read tools: `problem_get`, `problem_active_get`, `event_get`, `host_get`, `host_status_get`, `health_check`.

AIOps active-alert collection uses the core `problem_get` Monitoring API tool with bounded time/search/limit parameters. `ZABBIX_MCP_SERVER_NAME` is available for initMAX multi-server installations. Broad escape-hatch or mutation capabilities such as `zabbix_raw_api_call`, `action_prepare` and `action_confirm` are not exposed to reasoning agents or the EvidenceCollector.

Recommended deployment: create a dedicated initMAX MCP token with monitoring/alerts scopes, `read_only=true`, IP restrictions where possible, and bind it to the required Zabbix server.

## Elasticsearch

Upstream compatibility target: `elastic/mcp-server-elasticsearch` tools `list_indices`, `get_mappings`, `search`, `esql`, `get_shards`.

AIOps log Evidence maps to `search` using explicit `index`, `fields` and Elasticsearch Query DSL `query_body`. The index is constrained by `ELASTICSEARCH_MCP_INDEX_PATTERN`; the Agent never supplies an arbitrary index or arbitrary DSL directly.

Important lifecycle note: Elastic marks this standalone repository deprecated and recommends the Elastic Agent Builder MCP endpoint for Elastic 9.2+ and Elasticsearch Serverless. Therefore the AIOps domain adapter remains provider-oriented: deployments can replace the endpoint with the newer Elastic MCP service once its exposed tool contract is validated, without giving Agents direct Elasticsearch credentials.

## Transport

`integrations/mcp_client.py` implements standard Streamable HTTP lifecycle and response handling: `initialize`, `notifications/initialized`, negotiated protocol version, optional `Mcp-Session-Id`, JSON responses and SSE event responses. The compatibility baseline is `2025-03-26` because the referenced Elastic server explicitly advertises that protocol version; negotiation may select the version returned by the target server.

## Security boundary

Only allowlisted read tools are available to Evidence collection. External provider credentials remain with the MCP server/provider trust zone. Agent output is never converted directly into arbitrary tool names, PromQL, Elasticsearch DSL or Zabbix raw API calls. Any future write capability must remain behind Decision -> Policy -> Approval -> Execution and must use a separate execution identity.
