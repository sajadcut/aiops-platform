# Upstream MCP Provider Contracts

The AIOps Control Plane treats MCP as the canonical external-tool boundary. For the primary observability systems, adapters are aligned to actual upstream providers rather than invented local tool names.

## Prometheus

Upstream: `prometheus/prometheus-mcp`.

Supported read tools include `query`, `range_query`, `list_alerts`, `metric_metadata`, `series`, `label_names`, `label_values`, `healthy`, and `ready`.

AIOps metric collection maps canonical metric requests to `range_query` and builds deterministic PromQL from `PROMETHEUS_MCP_SERVICE_LABEL`. Destructive/admin tools remain excluded.

## Zabbix

Upstream: `initMAX/zabbix-mcp-server`.

Supported Control-Plane read tools include `problem_get`, `problem_active_get`, `event_get`, `host_get`, `host_status_get`, and `health_check`.

AIOps active-alert collection uses bounded `problem_get`. Broad/raw or mutation capabilities are not exposed to Evidence collection.

## Elastic

Canonical provider: **Elastic Agent Builder MCP**, served by Kibana.

Minimum supported Elastic Stack: **9.2**. Recommended Production baseline: **9.3+**, pinned to an approved patched release.

Endpoints:

- `{KIBANA_URL}/api/agent_builder/mcp`
- `{KIBANA_URL}/s/{SPACE}/api/agent_builder/mcp` for custom Spaces.

The deprecated standalone `elastic/mcp-server-elasticsearch` is intentionally unsupported and must not be deployed as an AIOps production dependency.

The Control Plane limits discovery to configured Agent Builder namespaces. `platform.core` is mandatory. Canonical log Evidence uses only `platform.core.execute_esql`; the adapter generates deterministic bounded ES|QL from trusted service/time/level inputs and the configured `ELASTIC_AGENT_BUILDER_INDEX_PATTERN`.

The Evidence path intentionally does not use `platform.core.search` or `platform.core.generate_esql`, because those capabilities introduce an additional AI/query-generation step. Agent Builder remains a capability provider, not the reasoning authority for the AIOps incident workflow.

Authentication for unattended AIOps access should use a least-privilege Elastic API key. The API key/Kibana role must have only the Agent Builder route privilege and index privileges required by the allowlisted tool. Space scoping should be used where it improves isolation.

## Transport

`integrations/mcp_client.py` implements Streamable HTTP lifecycle and response handling: `initialize`, `notifications/initialized`, negotiated protocol version, optional `Mcp-Session-Id`, JSON responses and SSE event responses.

## Security boundary

Only allowlisted read tools are available to Evidence collection. Agent output is never converted directly into arbitrary tool names, PromQL, ES|QL/Query DSL or Zabbix raw API calls. Future write capabilities remain behind Decision -> Policy -> Approval -> Execution and independent Verification.
