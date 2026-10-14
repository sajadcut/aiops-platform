# Incident Room: service health, Service Catalog and explainable decision state

## What an operator sees

The Incident Command Room separates five independently sourced facts:

1. **Trigger event:** the original Zabbix/Prometheus/Elastic alert is historical. “Service Down” is not a live claim.
2. **VM status:** the latest authenticated, incident-bound `service_status` observation shows systemd `active/running`, `failed`, `inactive`, etc., including timestamp and source. The operator can use **↻ بررسی مجدد** to run a read-only recheck.
3. **HTTP readiness:** distinct from systemd. It starts as **not configured / not checked** and becomes healthy/unhealthy **only** after an explicit HTTP probe to the SRE-configured service endpoint.
4. **Analysis:** Agent results describe the time of investigation, not current system state. Root-cause confidence and Evaluator confidence are separate. Generic `config_validate:unsupported` does not cancel a real `.NET JSON syntax` result.
5. **Execution governance:** absent or Evaluator-blocked recommendations are explicitly **no executable action**, not “unknown target, risk, runbook, outcome.” A real Approval, Binding and live preflight remain mandatory for any mutation.

No status, confidence, missing dependency, port, risk or successful verification is invented for demonstration.

## Persistent per-service profile

After the **m0n1o2p3q4r5** Alembic migration, PostgreSQL stores `service_health_profiles` with a unique `(service, target)` identity. Incident-bound service identity is verified against Zabbix tags and direct VM MCP evidence. Historical Agent summaries, LLM suggestions and user-supplied arbitrary hostnames are **not** usable as hosts for probes.

The profile includes:

- platform (`vm_systemd`, `windows_service` or `kubernetes`);
- owner (manual/SRE supplied);
- expected HTTP port and health path (both must be configured);
- HTTP or HTTPS scheme;
- dependencies (SRE supplied, never guessed from RAG);
- informational runbook ID, and verification notes.

Configuring a runbook name does **not** register, authorize or execute a runbook.

### API endpoints

| Method | Endpoint | Permission | Behavior |
| --- | --- | --- | --- |
| GET | `/api/v1/incidents/{id}/service-profile` | `read:incident` | Read current SRE configuration; do not call VM |
| PUT | `/api/v1/incidents/{id}/service-profile` | `manage:service_profile` (SRE) | Validate and upsert catalog record, audit; no execution |
| GET | `/api/v1/incidents/{id}/health-status` | `read:incident` | Read only the most recent matching audited probe |
| POST | `/api/v1/incidents/{id}/health/recheck` | `read:incident` + strict rate limit | Explicit read-only HTTP GET with bounded 3-second timeout and audit |

The health check restricts targets to the incident-bound **private IPv4**, denies loopback, public addresses, metadata/link-local destinations and user-provided URLs, and allows only a configured port and restricted absolute path. The client does not follow redirects, does not forward credentials or proxy configuration, and never displays response bodies. It only records HTTP status code, outcome, timestamp and source. The dedicated central **verified_async_client** factory enforces TLS certificate and hostname verification for HTTPS health checks; health probes must not carry secrets.

**A successful HTTP status is only a health endpoint response**, not proof of full application correctness or completed incident recovery.

## Operator setup (for GFPAPI)

1. Deploy the new `main` build and migrate the AIOps **database**, not the monitored VM. No Python is required on the monitored servers.
2. Open an analyzed GFPAPI incident. The top of the page contains systemd status, operational summary and **Service profile & application health**.
3. As an SRE, expand **ویرایش پروفایل سلامت**, verify the correct service/VM, then enter the actual owner, port and safe health path obtained from application configuration or documentation. Do **not** assume `/health`, a port, or any dependencies without verifying them.
4. Save. With a configured endpoint, click **بررسی زنده HTTP**. Green requires an actual 2xx response; timeout, connection errors and non-2xx are distinguished.
5. Use **↻ بررسی مجدد وضعیت سرویس** to independently confirm systemd. If the original Zabbix alert remains open despite Running, review the alarm lifecycle separately.

When the backend or migration is not deployed, requests can fail. Never silently synthesize profile or health values to make the demo appear green.

## Acceptance conditions

- Historical Zabbix Down and newer VM MCP Running are shown as separate facts.
- A failed/unavailable recheck cannot reuse old Running as a fresh success.
- Missing action/approval/runbook/verification is expressed as *not proposed / not executed / not applicable* rather than unknown.
- VM-specific incident shows Kubernetes cluster/namespace as not applicable, never as invented Kubernetes fields.
- No HTTP request occurs on page load, and no health check can be redirected to a different host.
- All service profile writes are RBAC-protected, audited, validated and non-executable.
- Database migration upgrades and downgrades pass, and the full regression/CI gates remain enforced.
- Real VM/HTTP integration tests are marked **REAL ENV REQUIRED** until actually executed on deployed infrastructure.
