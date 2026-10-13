# Full Elastic integration acceptance: MCP, logs, anomaly contract, webhook

Use this comprehensive **read-only** live probe in the same Python environment
as the AIOps service, after setting up `.env`. It uses the real
`ElasticsearchMCPClient`, including your Space URL and authentication.

~~~powershell
git pull origin main
python -m scripts.check_elastic_integration --service GFP_Backend --api-base-url http://localhost:8000
~~~

Omit `--api-base-url` if the AIOps API is not started. Omit `--service`
to derive the service value from the sampled document (its value is never
printed). The test uses the configured `ELASTIC_AGENT_BUILDER_INDEX_PATTERN`,
for example `1m-digitaloperation-gfpapi-*`.

## What it checks

1. Effective MCP endpoint, Namespace and auth-header presence (not credentials).
2. Local tool allowlist: no unexpected tool execution is permitted.
3. `initialize`, notification handshake and `tools/list` on live Kibana.
4. Real read-only `platform_core_execute_esql`, fetching at most one row.
5. Decoding the real `results -> tabular_data -> columns/values` MCP response.
6. Recognition of service/message/level/timestamp fields (ECS and known
   `Properties.*`/Serilog variants); field **names** only are printed.
7. Actual read-only ES|QL service filtering, with a five-row limit.
8. The real AIOps `get_logs` adapter over a small timestamp window, including
   service identity, message and timestamp validation. A working MCP tool is
   **not** sufficient to pass this check.
9. Offline active and recovery anomaly payload normalization/dedup identity.
10. Optional read-only GET `/openapi.json` to verify the AIOps webhook POST
    route and its authentication contract.

No raw log values, password, token, response body or service name is printed.
The Elastic MCP tool-call logger now suppresses both raw ES|QL queries and
response bodies rather than relying on a fixed body-size threshold. Run only
against authorized indexes with a read-only identity; HTTP Basic over unencrypted
HTTP remains insecure even though the test is read-only.

**This command does not send test webhooks**, activate an ML job, configure a
Kibana connector, create incidents, or validate active/recovery persistence.
Those require a separate staging acceptance run with actual Kibana rules,
connector credentials, PostgreSQL, and the AIOps API. Accordingly those
checks are explicitly `NOT TESTED`; they never receive an artificial PASS.

The CLI exit codes are:
- `0`: all available checks passed (reserved; currently real webhook/ML
  delivery is always NOT TESTED).
- `1`: a required live check failed.
- `2`: no required failures, but external acceptance work remains.

If `ES|QL read` succeeds and `AIOps LogEntry adapter` fails, confirm the
actual Elasticsearch mapping: the default adapter assumes ECS
`service.name`/`message`/`log.level`; your GFP index may instead use
`Properties.ServiceName.keyword`/`MessageTemplate`/`Level`.
Do not treat connector connectivity as Log Evidence readiness.

For CI, use the offline tests, which never call Kibana:

~~~powershell
python -m pytest -q tests/unit/test_check_elastic_integration.py tests/unit/test_elastic_mcp_wire_tool.py tests/unit/test_elastic_anomaly_ingestion.py
~~~

For historical/basic auth troubleshooting, the smaller connectivity-only
check remains available:

~~~powershell
python -m scripts.check_elastic_mcp
~~~
