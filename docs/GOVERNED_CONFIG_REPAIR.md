# Governed configuration repair — helperless VM execution

## Operator workflow / جریان اپراتوری

AIOps discovers the actual systemd service and config file, diagnoses the
failure, produces a deterministic hash-bound redacted Diff, changes **only a
private temporary copy**, independently checks the proposed candidate, and
presents the evidence and Diff for human Approval. Validation MUST NOT modify
the original production file.

After approval, the API requires separate execution confirmation, consumes the
high-risk approval once in PostgreSQL, creates a short-lived HMAC signed claim,
and sends it to the VM MCP worker. That worker **also verifies** the signature,
target/service/path/hashes and expiry before invoking a single trusted,
predefined POSIX transaction through the SAME SSH user's sudo privilege.
The transaction takes a root-only backup, checks the live source hash, performs
a same-directory atomic replacement, postchecks with the registered validator
and restores the exact original on a failed postcheck. Starting or restarting
a stopped service requires a separate service-recovery Approval.

**There is no VM agent or permanent config helper.** Trusted versioned
POSIX program source comes from integrations/vm/ephemeral_config_guard.py on
the VM MCP host and is streamed on SSH stdin to /bin/sh -s. Remote Python,
aiops-config-guard, a preinstalled public key file and any per-VM bootstrap
are NOT required. Noninteractive exact-byte patching is preferable to
interactive vi for automation because it is reproducible and verifiable.

## Trust boundary and authorized sudo

Eliminating the VM-root-owned guard deliberately moves the script trust
boundary into the VM MCP worker. The VM MCP's code, connected control-plane
authentication, HMAC key and SSH credentials are security-critical.

* The same SSH_USERNAME is used for SSH login and sudo. With password-mode
  SSH, the worker first tries sudo -n; if the policy requires a password, it
  retries sudo -k -S -p '' using the SSH user's configured password, followed
  by the fixed POSIX script on encrypted SSH stdin.
* The SSH user must be authorized to invoke root /bin/sh -s with sudo (as an
  administrator able to sudo su generally is). **This is wider privilege**
  than a policy that only allows /usr/local/sbin/aiops-config-guard.
  Hosts with helper-only sudo rights must remain blocked until independently
  authorized administrators change the privilege policy. AIOps NEVER modifies
  sudoers to work around denial.
* LLM output cannot define a privileged shell command or set an unverified
  path. File discovery comes from live systemd evidence; fixed deterministic
  repair profiles rebuild the exact hash-bound proposal from the live file.
  SSH argv contains only allowlisted operation, profile, path and hashes.
  Candidate bytes are encoded in an SSH-stdin heredoc, never stdout, logs,
  LLM, process argv, incident checkpoints or browser responses.
* MCP_BEARER_TOKEN is now the **only** shared signing root between API and
  VM MCP. Both must have the identical, high-entropy token (at least 32 UTF-8
  bytes). The claim HMAC uses a domain-separated key derived from that token
  using HMAC-SHA256 with context
  `aiops/configuration-apply/approval-claim/v1`, not the raw bearer bytes.
  No additional AIOPS_CONFIG_APPLY_SIGNING_SECRET setting is necessary.
  This couples MCP transport authorization with approval signing trust:
  possession of the MCP bearer can also derive the signing key. Protect and
  rotate the bearer appropriately, and retain DB approval consumption, bounded
  claims, hash binding, sudo policy, root-only replay ledger and rollback.
  AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY is no longer required by this path.
  No persistent VM helper needs deployment.

## Registered independent validators

| Bounded repair profile | Services | Pre-approval validation | Claim limit |
|---|---|---|---|
| One unexpected duplicate opening brace in .conf | nginx | Copy complete /etc/nginx to private staging; mount it read-only on /etc/nginx inside unshare -m; run /usr/sbin/nginx -t -c with original path | External includes may remain live read-only dependencies; no mount namespace -> BLOCK |
| One trailing JSON comma | Any live systemd-bound .NET/Java/Python/Tomcat/custom service | jq empty on staged file | JSON grammar only; not app schema/health |
| One unmatched XML closing tag | Any live systemd-bound Java/Tomcat/custom service | xmllint --nonet --noout on staged file, DTD/entities refused | XML grammar only; not app schema/health |

Other formats such as YAML, properties, INI, HAProxy or Apache remain
discovery/review only until separately registered, tested vendor
validation and bounded repair profiles exist. The LLM cannot use arbitrary
shell or guessed validators to make an Approval actionable.

## Dependencies, diagnostics, failure codes

Only standard Linux commands are used by the transaction: POSIX /bin/sh,
sudo, base64, sha256sum, stat, readlink, mktemp, flock, cp, mv and mkdir.
Nginx also needs mount, unshare and namespace permission; JSON requires jq;
XML requires xmllint. A missing required validator returns a prerequisite
failure and must not auto-install software or weaken isolation.

New safe log events: vm_config_ephemeral_transaction_started,
vm_config_guard_sudo_stage, vm_config_guard_validation_completed and
vm_config_guard_apply_completed. All include bounded status/exit code and
no candidate bytes or passwords. Helper preflight logs are legacy only;
the new pipeline does NOT probe /usr/local/sbin/aiops-config-guard.

Stable failure codes: 41 bad request; 42 prerequisite; 43 candidate hash;
44 lock; 45 changed live source; 46 staging; 47 vendor syntax;
48 rolled back; 49 rollback failed; 50 mount namespace unavailable;
51 isolated mount failed. Human approval never follows a blocked validation.

## Required production acceptance

Real representative VM acceptance must prove: password sudo and multi-line
script stdin, private nginx mount namespace, snapshot/source-hash drift,
expired/forged claim rejection, hash/ACL ownership preservation, single-use
approval and second confirmation, post-write check, forced rollback, and
negative tests for unauthorized sudo and unavailable namespaces. CI mock
tests cannot prove these host-level properties. Label untested host scenarios
REAL ENV REQUIRED and never claim production-ready without verification.


## 2026-10-15 execution blocker: derived MCP bearer approval signing

Earlier deployments could reach `approved` after an isolated vendor check,
then fail at `POST /api/v1/approvals/{approval_id}/execute-config` with HTTP
503 `config_signing_key_not_configured`. The legacy dedicated signing secret
has now been removed. **The existing MCP_BEARER_TOKEN is the single source**
for both transport authentication and derived approval signing.

### Operator checklist

1. Ensure `MCP_BEARER_TOKEN` is set to **exactly the same** cryptographically
   random value (at least 32 UTF-8 bytes) in the **API** and **VM MCP** process
   deployments. Do not generate a second, unrelated token. Set it through a
   deployment secret manager or a locked-down development `.env`.
2. Restart both services after injecting any corrected secret. A previously
   approved request is still approval-bound to the original/candidate hashes;
   recheck live file drift before applying.
3. The Incident configuration-review response reports
   `execution_prerequisites.signing_source=MCP_BEARER_TOKEN` and
   `api_signing_key=derived_from_mcp_bearer_token` when the API's token is
   strong enough. It reports `missing_or_weak_mcp_bearer_token` otherwise.
   Remote MCP identity and token match are **not** asserted from an API-local
   check; the signed claim is verified by VM MCP during the actual operation.
4. Only after separately confirming a valid Approval should the operator
   select explicit execution. Missing/weak token is a pre-consumption 503 and
   does not change an independently confirmed syntax validation into FAIL.

Example on **Windows PowerShell**, launching both processes with an existing
secret from a secured file:

```powershell
$env:MCP_BEARER_TOKEN = (Get-Content 'C:\secure\aiops-mcp-token.txt' -Raw).Trim()
# Launch the API or VM MCP from this terminal.
```

The example file is not created by AIOps and must be ACL-restricted to the
service account. Production and Windows services need real service-level
secret injection; terminal variables are not inherited by unrelated running
services. **Never** paste or commit the value.

### Security trade-off

This is not independent cryptographic authorization: anyone obtaining the
MCP_BEARER_TOKEN can derive the signing subkey. Purpose separation prevents
accidental cross-protocol raw-key use but does **not** prevent impersonation
after the shared root is stolen. Do not expose the token to browsers, logs,
LLMs or incident reports. Existing DB consumption, expiry, hash/file/target
binding, no-write-before-approval and SSH/sudo policy still apply. For
production environments requiring distinct transport and privileged-action
trust roots, prefer separate credentials instead; this single-token design
intentionally trades separation for simpler operations.

Real VM and CI execution remain **REAL ENV REQUIRED** until independently
verified.


## Incident down-alert end-to-end recovery contract (2026-10-15)

A configuration syntax repair is NOT equal to incident recovery. A Zabbix
alert such as `nginx Service Down` requires the service to be running again.

For **new** config-change requests in the Incident Room, when a verified
systemd observation for the incident's bound VM/service is `failed` or
`inactive`, the user can submit a combined scope:

`start_service_after_apply=true`

The confirmation text explicitly states both effects before the ticket is
created, and the high-risk Approval and execution confirmations repeat the
combined scope. This Boolean is stored **immutably in the ticket's approval
metadata**, not added to a previously approved or consumed ticket.

At execute time the API issues the normal short-lived signed HMAC claim,
adding the only allowed optional `recovery_action=start_service` field for
a ticket whose original approval metadata contains that scope. VM MCP
verifies **all** signed fields and binds target, service, path and hashes
before apply. The transaction atomically replaces the config, runs the
vendor postcheck and reports `applied_verified`. **Only then** can the
trusted VM MCP invoke the allowlisted `systemctl start <verified service>`
once. Immediately before starting, it rechecks the same target/service via
systemd: `active` is a no-op; only `failed`/`inactive` plus
`load_state=loaded` can be started. After starting, the MCP checks systemd
again. No restart loops, speculative starts, automatic sudoers changes or
model-generated shell commands are permitted.

A response reports separate facts:
- `status=applied_verified`: candidate applied and vendor-checked
- `service_start_attempted`: whether one start was sent
- `service_recovery_status`: `systemd_active`, `already_active`,
  `start_failed`, `start_not_verified`, `precheck_unavailable`,
  `service_state_not_startable`, or `not_authorized`
- `service_recovery_confirmed`: observed systemd active after action
- `monitor_recovery_confirmed=false`: do not conflate local running with
  alert-source recovery

A Zabbix PROBLEM incident can become Resolved by either of two clearly
attributed and audited routes:

1. A matching authoritative **Zabbix RECOVERY** webhook (monitor recovered).
2. An explicit operator/SRE read-only service recheck or approved post-config
   recovery workflow that verifies the *same bound VM and service* in two
   independent live MCP reads, both `ActiveState=active` and
   `SubState=running`, and (for nginx) a successful live vendor
   `config_validate` check. The original Zabbix alert must explicitly
   describe the same systemd service as **down**; any additional correlated
   alert blocks this local closure. This is recorded as
   `independent_recovery`, `monitor_recovered=false`, not as a fake Zabbix
   Recovery event. A read-only **viewer** can recheck the service but cannot
   finalize/resolve the incident or revoke Approvals; it takes
   `approve:low_risk` permission (operator/SRE). Status mutation, cancellation
   of unconsumed Approvals and audit insertion use one DB transaction.

A mismatch, missing second observation, failed syntax check, lack of privilege
or failed start must be prominently visible; none can falsely close the
incident. `active/exited` is not service recovery for these long-running
units. An already-consumed **config-only** approval cannot gain service-start
permissions retroactively; use a separately approved service-recovery action
for legacy incidents.

### HTTP 500 during post-approval Incident chat

The two 500s at 2026-10-15 15:23 UTC were caused by writing
`evidence_recorded_reanalysis_requires_workflow_review` into
`audit_events.status VARCHAR(50)`. The canonical domain status stays
unchanged, and the audit record stores `reanalysis_requires_workflow_review`
plus `metadata.followup_status` containing the complete domain code.
This prevents the caught, non-reassessable chat follow-up from turning into
a database exception. The upstream Cognia health-check 500 in the same
log is an unrelated external dependency failure.

**REAL ENV REQUIRED:** Verify both the unchanged old approval and the newly
scoped combined Approval on a disposable VM with working systemd/SSH/sudo,
database persistence, vendor validation, service activation and a real
matching Zabbix recovery notification. Automated Python/JS unit regressions
alone cannot prove these external behaviors.
