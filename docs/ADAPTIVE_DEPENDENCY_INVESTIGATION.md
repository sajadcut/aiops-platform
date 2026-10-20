# Adaptive service-dependency investigation

## Purpose and boundary

Alerts mentioning Redis, relational databases, message brokers, or outbound
HTTP trigger *read-only* investigation of the **consumer application**, not a
guess that a local `redis.service` (or equivalent server process) is broken.

The trusted control plane identifies the reported service, resolves only
configured aliases, and confirms the actual systemd unit with VM MCP
`service_status` on an explicitly pre-allowlisted target. This is mandatory
before an Elasticsearch/Zabbix/Prometheus host label can start a VM check.
The LLM can request only a registered read-only check **name**. No LLM output,
Cognia text or alert-supplied string becomes a shell command, file path, VM
target, port, URL, authorization or configuration patch.

## Observability sequence

1. Ingest source alert and preserve the original trigger ID and text.
2. Discover the host from scoped Elasticsearch logs, or bound asset metadata
   from Zabbix/Prometheus; enforce the configured VM target allowlist.
3. Independently verify the systemd unit on that VM, including matching
   target, service name and loaded state.
4. Use VM MCP `service_config_discovery` to check systemd-derived config
   locations; for .NET this also inventories `appsettings*.json` in the
   verified publish directory. Python is not required on the managed VM.
5. Read only bounded verified files inside the VM worker; parse
   JSON / YAML / TOML / XML / properties / INI as supported. Persist **only**
   structural key provenance, protocol kind, allowed hostname and port.
   Secrets and raw connection strings do not leave the worker.
6. Test static endpoints from the **consumer VM**. For Redis, attempt TCP
   first; when unreachable, check DNS and (where resolvable) route. When
   reachable, optionally use installed `redis-cli` for an *unauthenticated*
   PING, with TLS enabled only when the config indicates rediss/ssl=true.
   A PONG supports basic Redis protocol responsiveness; NOAUTH indicates an
   authentication requirement. Neither verifies the application's credentials,
   selected database, timeouts, pool or business operation.
7. Select further read-only MCP checks with the LLM only after grounding it
   in the actual collected typed statuses. Re-verify host and service proof
   when dispatching the selected checks. Report unsupported tests as
   unsupported, not as healthy.
8. Keep provider/command results and provenance in Incident evidence,
   including fresh diagnostics on deduplicated alerts; surface technical
   findings in the decision brief and incident copilot.

## Important limitations

- Several files under a .NET publish directory can contain different
  endpoints. The actual effective environment / precedence, EnvironmentFile,
  dynamic provider and runtime overrides are not guaranteed by *file
  existence*. Until independently determined, all such findings are
  **candidate configuration evidence**, not proof of effective settings.
- Redis PING deliberately never issues AUTH or transmits passwords. A
  downstream authentication diagnosis requires a separately authorized,
  credential-safe path; protocol-level application success is not claimed.
- Non-Redis dependencies currently use bounded TCP or HTTP HEAD of the
  configured origin; this is transport evidence, never full protocol health.
- Missing `redis-cli` is recorded as unsupported; do not attempt to install
  Python or extra agents on remote VMs to compensate.
- No model-suggested filesystem scan, arbitrary hostname probe or write action.
  Changes continue to require the existing proposal, independent validation,
  policy, human Approval and independent post-action verification.

## Reproduction/acceptance

Use `tests/unit/test_adaptive_dependency_diagnostics.py`,
`tests/unit/test_elastic_verified_dependency_route.py`, and
`tests/unit/test_universal_dependency_investigation.py`.
Check at least these scenarios:

- ELK `GFP_Backend` -> independently verified `gfpapi` on
  `10.248.16.82`: `service_status -> dependency_investigation`.
- Redis endpoint read from a *verified* `appsettings.Production.json`:
  show path, structural key, host/port, TLS hint, TCP, protocol status.
- DNS failure: record `dns_resolved=false`, do not fabricate route/PING.
- `NOAUTH`: state that the server answered but client credentials are
  **not verified**; do not claim incorrect password.
- HTTP/ActiveMQ/SQL: preserve kind and file provenance; do not treat
  TCP success as full service health.
- Unknown or unallowlisted host: no VM tool call.
- Repeated alert ID: refresh evidence without replaying remediation.
- Attempted LLM Write operation or arbitrary destination: dispatch denied.
- Entire output remains secret-safe and `root_cause_confirmed=false`.

GitHub CI is necessary but not sufficient. Actual endpoint protocol,
credentials, Zabbix/Prometheus label mapping, VM worker allowlists, and
application behavior require real-environment tests and must be reported
as REAL ENV REQUIRED until observed.

## LLM-assisted, file-backed host/port binding

A dependency error must be investigated against the **service's verified config file**, not a vendor-default port. The VM MCP worker discovers a candidate through systemd/service configuration discovery, verifies file existence, securely reads the full file and parses JSON/JSONC, YAML, properties, XML or other supported structured formats. Raw config and secrets remain inside the trusted worker.

The optional LLM step in `integrations/vm/dependency_llm_binding.py` receives only a bounded, allowlisted projection: structural host/port field paths and validated host/port scalar values. It selects field **IDs** instead of proposing new values. The worker independently resolves selected IDs against its own parsed document and verifies the same dependency family/scope and an explicit, valid port. Only then is a bounded TCP/HTTP probe permitted. The model **cannot** authorize arbitrary host/port scanning, change targets, return credentials, modify files or execute remediation. If a sibling group has multiple plausible ports and no verifiable association, no speculative probe is performed.

Example (verified service configuration):

```json
{
  "Redis": {
    "Endpoints": {"Primary": {"Host": "10.248.34.221"}},
    "ConnectionOptions": {"TcpPort": 6389}
  }
}
```

A successful model selection of the existing `Redis.Endpoints.Primary.Host` and `Redis.ConnectionOptions.TcpPort` IDs yields the **literal** endpoint `10.248.34.221:6389` with `port_inferred=false`, `config_key`, `config_port_key`, `config_file` and `endpoint_source=llm_binding_independently_verified`. No check on 6379 is justified by these values. If the endpoint is not verifiable, emit `port_unverified` or the model-binding diagnostic; never manufacture a successful TCP connection.

### Runtime configuration and status

To use this step, the **VM MCP process** (which executes the trusted config read) must have its own valid `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL` and, if required by the provider, `LLM_API_KEY` configuration. The model endpoint must use HTTPS (loopback HTTP is allowed for local development). Configuring an LLM **only** in the API process does not activate model calls from the separate VM MCP process. No extra signing keys are introduced.

The read-only `dependency_investigation` response reports `llm_field_binding_status` and bounded `llm_field_binding_files` metadata. Examples include `verified`, `trusted_llm_not_configured`, `no_safe_host_port_candidates`, `llm_response_invalid`, `llm_cross_dependency_selection` and `llm_binding_unavailable`. The existing strict parser can still discover and test explicitly configured endpoints if the LLM is unavailable; this fallback must be shown as deterministic rather than attributed to an LLM.

Deployment acceptance requires a **real** VM MCP read and observed TCP outcome on the application's effective configured port. Unit tests are not a substitute for it. Compare the config source keys with the application's active environment overrides and verify that any dynamically injected endpoint is either independently resolved or explicitly marked `effective_endpoint_unverified`.

## Multi-stack endpoint extraction (PostgreSQL, MySQL, SQL Server, Oracle, MongoDB, ActiveMQ, Kafka, RabbitMQ and others)

This is not a Redis-only check. The same trust boundaries and evidence rules apply to SQL/NoSQL databases, message brokers and externally configured HTTP clients. Supported structured config inputs include bounded JSON/JSONC, YAML, TOML, XML and Java `.properties`/INI-like files from independently verified service paths. In addition to host and port fields, the trusted parser recognizes explicit host:port literals in JDBC URLs, SQL Server DSNs, AMQP(S)/Redis URIs, ActiveMQ `failover:(tcp://host:port,...)`, Kafka `bootstrap.servers`, MongoDB replica-set connection URIs and Cassandra contact-point lists with a configured parent port.

For a separate Host/Port pair, the optional LLM returns existing field IDs. For URL/Connection String/Bootstrap list, a trusted parser first extracts an allowlisted, explicit literal destination; the LLM can select **only its pre-extracted endpoint ID** (never arbitrary host, port, URI, credentials or command). The agent rechecks every selection against the exact parsed config, records provenance and applies the existing bounded probe budget. Independently verified deterministic endpoints are still available if the model fails. A vendor-default, dynamically substituted, or MongoDB SRV-provided port is not verified and MUST NOT be reported as a successful app-port test.

For Kafka, a successful TCP probe of the bootstrap broker does **not** verify broker metadata, advertised listeners, leader/partition availability, consumer lag, SASL/TLS/auth or successful produce/consume. For ActiveMQ/RabbitMQ it does **not** verify queue/consumer state, authentication or delivery. For SQL/NoSQL it does **not** verify login, TLS validation, pool, query success or replication. Redis is the only dependency currently offering the additional optional unauthenticated protocol PING; non-Redis endpoints use bounded TCP or configured HTTP HEAD, with protocol/application health explicitly unverified.

Per-file `candidate_host_count`, `candidate_port_count`, `candidate_inline_endpoint_count` and `verified_pair_count` are returned as *non-secret* diagnostic metadata. When a file is parsed but no trustworthy endpoint is extracted, the dashboard must report missing/ambiguous evidence rather than a guessed port. The **on-target bundled vmmcpagent executable** must be rebuilt/redeployed to receive these features; updating only the API or dashboard is not sufficient.

## 2026-10-19: database alarm with unrelated Redis probes

The `GFP_Backend` database-connection test exposed two independent diagnostic failures. One parsed service config yielded six eligible Host/Port fields but the VM MCP worker reported `trusted_llm_not_configured`. Three later parsed files had no candidates, and the aggregate field-binding status previously incorrectly became `no_safe_host_port_candidates`. The aggregate now preserves the most relevant encountered failure while each file retains its own status.

A `dependency_investigation` call may successfully parse 4 files and execute 6 TCP checks **without testing the technology named in the received alert**. For example, all six checked endpoints may be Redis or HTTPS even though the alert concerns a SQL database. The alert-focused report now exposes the actual `alert_family`, `matching_endpoint_count`, and `other_dependency_kinds`. The Persian Incident Room explicitly says when no database endpoint was tested and separates unrelated network results. A per-file round-robin and one-representative-per-technology ordering helps a later SQL/Kafka/MQ endpoint share a fixed probe budget with a Redis cluster; this does not authorize any new destination or guarantee all configured peers were checked.

The VM MCP process requires its own trusted `LLM_BASE_URL` and `LLM_MODEL` (plus `LLM_PROVIDER` and a provider token when necessary). A separate API-side LLM setup or a successful LLM call in an incident report does not activate `dependency_config_field_binding` in a PyInstaller-built on-target agent. Never place tokens in logs or in webhook fields.

The same incident reported `vm_canonical_unit_mismatch`: alert label `GFP_Backend` requested `gfp_backend`, but systemd returned canonical unit `gfpapi`. This mismatch must not be silently accepted as execution authority. After confirming the two names designate the same loaded unit, explicitly configure `ELASTIC_SERVICE_DISCOVERY_ALIASES={"gfpapi":["GFP_Backend"]}` in the API, restart its process and recheck host discovery. Rebuilding the on-target agent is necessary if its code is stale. If the mapping cannot be independently verified, leave binding unverified and require human review.

Finally, a received test webhook describing 10 database errors is a monitoring signal, **not evidence that the database itself is down**. If no actual DB connection string/Host/Port has been discovered, the correct disposition is unverified, even if Redis TCP succeeded. No database credentials or SQL write operations are required for this diagnosis.

## Central AIOps dependency reasoning (control-plane only)

### Optional full-context internal LLM mode (2026-10-20)

The default two-phase dependency workflow continues to project **only** bounded
non-secret field IDs and literal endpoints. For incidents that require a model to
inspect all application configuration values (including `ConnectionStrings`,
`User ID`, `Password`, API endpoints, usernames and credentials), the
operator can explicitly enable a second, transient mode. This mode is not enabled
by merely configuring `AIOPS_FULL_CONFIG_LLM_ENABLED`: that separate setting is
for syntax-repair previews and does not enable dependency diagnosis.

Set `AIOPS_DEPENDENCY_LLM_FULL_CONFIG_ENABLED=true` in both **AIOps API** and
**VM Agent / VM MCP worker**. On the API set
`AIOPS_DEPENDENCY_LLM_APPROVED_HOSTS=["your.internal.llm.hostname"]` and
`LLM_BASE_URL=https://your.internal.llm.hostname/v1`. If the internal CA is
not in the OS certificate store, configure
`AIOPS_DEPENDENCY_LLM_CA_BUNDLE_PATH=/path/to/trusted-ca.pem` on the API.
Only exact, approved HTTPS hostnames can receive complete configuration. The
central adapter verifies TLS certificates and hostnames for both this mode and
complete-file syntax-repair prompts, instead of disabling TLS verification.

In `dependency_investigation(mode=discover,include_full_config=true)`, the
worker reads a systemd-verified config file, parses it, returns its bounded
host/port IDs and (only for files <=64 KiB) the **entire raw source** in a
transient base64 field. This base64 is only an encoding, not encryption; the MCP
or Agent transport must be authenticated and confidential. The API verifies
source SHA-256 against those exact bytes, removes the raw payload from the MCP
result, and sends the complete decoded content to its configured internal LLM
only. The model is still restricted to returning existing candidate IDs. The
worker rereads and validates those IDs and the source hash before any read-only
probe. Neither passwords nor the source document are placed in incident
evidence, Cognia, chat history, frontend responses or MCP request/response
logs. Files over the size cap are **not silently truncated**; they continue to
use the bounded non-secret projection.

A full-text prompt does not guarantee extraction of an endpoint: if the local
parser failed to create independently verifiable database candidate IDs, the
LLM may explain ambiguity but cannot invent a probe destination. Likewise,
service alias verification and VM Agent version compatibility are mandatory;
`agent_upgrade_required` is a deployment failure, not a model diagnosis.
The user must rebuild and redeploy the **on-VM vmmcpagent executable**, update
the API and VM MCP together, and validate the endpoint and prompt coverage with
a real incident. No Python installation is required on managed hosts.


**The VM Agent does not need an LLM endpoint or API key for dependency
investigation.** The API owns all model inference, and the host worker owns
config parsing, identity verification, independent SHA/field-ID checks and
bounded read-only connectivity probes.

1. Match the exact service named in the received Zabbix/ELK alert. If the
   requested systemd alias returns a different canonical Id, it is accepted
   **only** when the read-only `systemctl show Names` inventory explicitly
   contains both names for the same loaded unit, or after an operator-declared
   mapping is independently verified. Never infer `GFP_Backend=gfpapi` from
   similarity or a past incident.
2. Request `dependency_investigation(mode=discover)` over the existing
   authenticated VM MCP/agent-pull channel. The worker rereads only
   systemd-verified bounded config files and returns non-secret structural
   Host/Port field IDs, JDBC/Kafka/ActiveMQ inline endpoint IDs, source paths
   and SHA-256 of the source bytes. This phase performs **zero probes**.
3. The AIOps API invokes its own `LLM_PROVIDER`, `LLM_BASE_URL`,
   `LLM_MODEL`, `LLM_API_KEY` via
   `central_dependency_config_binding`. The model sees only the matching
   alert family and chooses previously listed IDs. An invented ID is ignored.
4. Send only file indices, SHA-256, and selected IDs via
   `dependency_investigation(mode=probe)`; never send model-proposed
   hostnames, ports or commands. Worker independently rereads the actual
   config, rejects changed hashes/cross-wired Host/Port scopes, and tests
   only verified destinations *of the incident's dependency family*.
   Vendor-default or inherited guesses do not establish app connectivity.
5. Independently classify exact-service journal and decoded Elasticsearch
   DB/broker/cache errors into bounded signatures (refused, timeout,
   authentication, pool exhaustion, DNS, TLS, reset), correlate those with
   relevant transport checks, and submit **signatures only** to the central
   `central_dependency_error_correlation` model. Its Persian explanation
   is a **hypothesis**, not proof of root cause, unless a separate validator
   and evidence establish it. Unparsable ELK MCP envelopes must be marked
   `response_format_unrecognized`, not `0 matching errors`.

A valid DB incident with Redis/HTTP config but no DB endpoint yields
`alert_dependency_not_discovered` and no unrelated network probes.
If the central model is unavailable, the worker still safely probes
independently parsed explicit same-family endpoints, but it cannot assert
a model-verified split-field binding. Full credentials, connection strings,
SQL statements and raw log lines must not enter the selection LLM prompt.

**Deployment**: update API, VM MCP and *on-target vmmcpagent binary*
together to support both phases and the `Names` live alias proof. Do not
configure any LLM gateway in the VM Agent for this diagnosis.
A legacy agent or a network response returning HTTP 200 does not count as
runtime acceptance. Run a staging/VM incident check before claiming success.
