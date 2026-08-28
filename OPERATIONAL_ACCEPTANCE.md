# Operational Acceptance Gate

This is the production-like staging gate for `aiops-platform`. A scenario is **PASS only when the JSON evidence produced by the runner proves a real injected failure was observed by monitoring, became an AIOps incident, produced persisted evidence/RCA/decision, respected approval, executed through the normal control plane when applicable, verified recovery, and wrote the required audit trail.** Code review or mocked CI does not qualify.

## Hard safety rules

- Never run destructive scenarios against `prod`, `production`, or `live`.
- Destructive scenarios require `AIOPS_TEST_ENV=staging|lab|test`, `ALLOW_DESTRUCTIVE_TESTS=true`, an explicit target allowlist, an explicit typed fault-action allowlist, and a rollback contract.
- The runner does **not** execute arbitrary shell/SSH/kubectl commands. Failure injection goes through a dedicated staging-only typed Fault Injector API. Remediation is never performed by the test runner; AIOps must traverse Decision → Policy → Durable Approval → signed execution capability → MCP write → Verification.
- `AIOPS_TEST_AUTO_APPROVE=true` is optional and only simulates the human approval click through the real AIOps approval API. It never bypasses Approval/Execution boundaries.
- Cleanup exists only to restore the staging test fixture after timeout/crash; cleanup is not counted as AIOps remediation.

## Run

```bash
set -a
source operational.env.local
set +a
python -m tests.operational.run_operational_acceptance --environment staging --all
```

Single scenario:

```bash
python -m tests.operational.run_operational_acceptance --environment staging --scenario VM-SERVICE-DOWN
```

Reports are written under `artifacts/operational-acceptance/` as one JSON file per scenario plus `summary.json`. Required evidence fields include timestamps, correlation ID, incident ID, approval ID, execution ID, evidence IDs, RCA/evaluation, remediation result, verification result, monitoring observations, lifecycle state, and audit events.

## Staging Fault Injector contract

The runner expects a **separate staging-only** service:

- `POST /inject` accepts `{scenario_id, correlation_id, environment, target, action, parameters}`.
- `POST /cleanup` accepts the same envelope with the scenario rollback action.
- It must reject production targets and unknown actions independently of the runner.
- Actions are typed (`vm.stop_service`, `kubernetes.oom`, `postgres.deadlock`, etc.); no arbitrary command field is accepted.
- It must be scoped to disposable/allowlisted staging targets and return non-2xx when injection/cleanup did not actually occur.

## Acceptance status

All scenarios start at **NOT RUN**. `PASS` may only come from a real staging execution report. `BLOCKED` means required staging configuration/integration is absent. `FAIL` means the real system violated the scenario contract. `PARTIAL` is documentation-only and is never equivalent to readiness.

| Scenario | Purpose | Initial status |
|---|---|---|
| VM-SERVICE-DOWN | real systemd service outage → detection/RCA/approved recovery | NOT RUN |
| APP-CRASH | process crash | NOT RUN |
| APP-HTTP-5XX | 5xx spike | NOT RUN |
| APP-LATENCY | latency/SLO breach | NOT RUN |
| HOST-CPU-SATURATION | CPU saturation | NOT RUN |
| HOST-MEMORY-OOM | memory pressure/OOM | NOT RUN |
| HOST-DISK-FULL | disk exhaustion | NOT RUN |
| HOST-INODE-FULL | inode exhaustion | NOT RUN |
| PG-CONNECTION-EXHAUSTION | PostgreSQL connection pressure | NOT RUN |
| PG-DEADLOCK | PostgreSQL deadlock diagnosis, no unsafe restart | NOT RUN |
| PG-SLOW-QUERY | slow query/lock diagnosis | NOT RUN |
| K8S-CRASHLOOP | CrashLoopBackOff | NOT RUN |
| K8S-OOMKILLED | OOMKilled | NOT RUN |
| K8S-READINESS-FAIL | readiness failure with liveness distinction | NOT RUN |
| K8S-BAD-ROLLOUT | bad deployment → rollback candidate | NOT RUN |
| NETWORK-DNS-FAIL | DNS failure | NOT RUN |
| NETWORK-PACKET-LOSS | packet loss/timeout | NOT RUN |
| DEPENDENCY-OUTAGE | downstream dependency outage | NOT RUN |
| OBS-ELASTICSEARCH-DOWN | ELK evidence-source outage | NOT RUN |
| OBS-PROMETHEUS-DOWN | Prometheus outage | NOT RUN |
| OBS-ZABBIX-DOWN | Zabbix outage | NOT RUN |
| IDENTITY-JWKS-FAIL | OIDC/JWKS outage without auth bypass | NOT RUN |
| CONFIG-REGRESSION | configuration regression | NOT RUN |
| TLS-CERT-FAIL | certificate/TLS failure | NOT RUN |
| MESSAGING-CONSUMER-LAG | queue/consumer lag when messaging exists | NOT RUN |
| RECOVERY-BACKUP-FAIL | backup/recovery protection failure | NOT RUN |
| FALSE-POSITIVE-ALERT | healthy target + false alert must not cause write | NOT RUN |
| CONFLICTING-TELEMETRY | conflicting sources lower confidence | NOT RUN |
| MISSING-TELEMETRY | partial observability fails safe | NOT RUN |
| MCP-TIMEOUT | write MCP timeout, no unsafe retry/resolved state | NOT RUN |
| LLM-TIMEOUT | model outage without fabricated RCA/write | NOT RUN |
| LLM-UNSAFE-OUTPUT | unsafe model recommendation blocked | NOT RUN |
| REMEDIATION-FAILURE | failed write never proceeds to successful resolution | NOT RUN |
| VERIFICATION-FAILURE | successful write + failed post-check never resolves | NOT RUN |
| APPROVAL-REJECTED | rejection prevents execution | NOT RUN |
| APPROVAL-EXPIRED | expired approval prevents execution | NOT RUN |
| DUPLICATE-SIGNAL | same source event is deduplicated | NOT RUN |
| REPEATED-INCIDENT | recurring fault after closure becomes a new occurrence | NOT RUN |
| CONCURRENT-INCIDENTS | unrelated simultaneous failures never cross-correlate/actions | NOT RUN |

## Scenario contract

Every YAML scenario in `tests/operational/scenarios/` records: Preconditions, typed Failure Injection, expected Zabbix/Prometheus/ELK observation, Incident expectation, correlation/dedup behavior, Evidence, expected Agent routing, RCA, confidence/missing-evidence behavior, Decision, Approval requirement, remediation, tool/action intent, Verification, rollback, timeout, and required audit events.

## Product readiness rule

The product is **Operationally Ready only when every scenario applicable to the deployed feature set is PASS in the target staging topology and there are zero unresolved FAIL/BLOCKED scenarios for production-required capabilities.** Messaging/recovery scenarios are applicable only when those features are deployed, but they cannot be called supported until their scenario is PASS.
