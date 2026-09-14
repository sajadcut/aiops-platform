# Upstream MCP Provider Contracts

The AIOps Control Plane treats MCP as the canonical external-tool boundary. For the primary observability and operational systems, adapters are aligned to actual upstream providers rather than invented local tool names.

## Prometheus

Upstream: `prometheus/prometheus-mcp`.

Supported read tools include `query`, `range_query`, `list_alerts`, `metric_metadata`, `series`, `label_names`, `label_values`, `healthy`, and `ready`.

AIOps metric collection maps canonical metric requests to `range_query` and builds deterministic PromQL from `PROMETHEUS_MCP_SERVICE_LABEL`. Destructive/admin tools remain excluded.

## Zabbix

Upstream: `initMAX/zabbix-mcp-server`.

This is the **only supported Zabbix runtime boundary**. AIOps does not contain a native/direct Zabbix API connector and does not accept `ZABBIX_URL`, `ZABBIX_USERNAME`, `ZABBIX_PASSWORD`, or `ZABBIX_TIMEOUT_SECONDS` runtime settings.

The AIOps client connects to the upstream `/mcp` endpoint using `ZABBIX_MCP_URL`. When the initMAX server is protected by an MCP token, configure the complete `Authorization` value in `ZABBIX_MCP_AUTH_HEADER`, normally `Bearer <mcp-token>`. The Zabbix API token used by initMAX to authenticate to Zabbix belongs in the initMAX server configuration, never in the AIOps Control Plane.

Supported Control-Plane read tools include `problem_get`, `problem_active_get`, `event_get`, `host_get`, `host_status_get`, and `health_check`.

AIOps active-alert collection uses bounded `problem_get`. Broad/raw or mutation capabilities are not exposed to Evidence collection.

## Jenkins

Upstream: the official Jenkins `mcp-server` plugin (`jenkinsci/mcp-server-plugin`, plugin ID `mcp-server`).

The canonical AIOps transport is the plugin's **Streamable HTTP** endpoint:

- `{JENKINS_ROOT_URL}/mcp-server/mcp`
- health: `{JENKINS_ROOT_URL}/mcp-health`

The supported upstream contract uses MCP specification `2025-06-18`. `JENKINS_MCP_PROTOCOL_VERSION` is therefore pinned to `2025-06-18` until the provider contract is deliberately upgraded and regression-tested.

Jenkins authentication uses the same Jenkins identity as the controller: a Jenkins API token is sent with HTTP Basic authentication. `JENKINS_MCP_AUTH_HEADER` must contain the complete value `Basic <base64(username:api-token)>`; AIOps does not accept a Jenkins password/token as a separate raw setting. Production also configures `JENKINS_MCP_EXPECTED_IDENTITY`; health checks call `whoAmI` and fail closed when the server reports `anonymous` or an unexpected principal. `JENKINS_MCP_ORIGIN` may be configured when the Jenkins MCP endpoint enforces Origin matching.

Read-only tools allowlisted by `JenkinsMCPClient` are:

- `getJob`, `getJobs`, `getQueueItem`
- `getBuild`, `getBuildLog`, `searchBuildLog`, `getReplayScripts`, `getTestResults`
- `getJobScm`, `getBuildScm`, `getBuildChangeSets`, `findJobsWithScmUrl`
- `whoAmI`, `getStatus`

Mutating upstream tools are classified separately: `triggerBuild`, `updateBuild`, `rebuildBuild`, and `replayBuild`. They are disabled by default. Enabling them requires `JENKINS_MCP_ENABLE_WRITES=True`, a separate `JENKINS_MCP_WRITE_AUTH_HEADER`, and the AIOps governed write method requiring Approval ID, Incident ID, and execution-capability context. Direct generic `call_tool` access to Jenkins write tools is rejected. MCP write requests are not retried because a lost response after a remote side effect is ambiguous.

The client exposes convenience wrappers with bounded pagination/search sizes rather than forwarding arbitrary free-form Jenkins tool calls from Agent output. The build-log wrapper supports the upstream cursor contract for non-blocking incremental reads.

This implementation provides the Jenkins MCP client and readiness boundary. It does **not** by itself declare Jenkins remediation/action acceptance complete; production write registration, policy mapping, rollback/verification objectives, and real Jenkins acceptance remain separate work.

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

Only allowlisted read tools are available to Evidence collection. Agent output is never converted directly into arbitrary tool names, PromQL, ES|QL/Query DSL or Zabbix raw API calls. Jenkins write tools remain behind explicit opt-in plus the Decision -> Policy -> Approval -> Execution boundary. Independent Verification is still required before Jenkins actions can be treated as production-accepted remediation.
