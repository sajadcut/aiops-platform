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
