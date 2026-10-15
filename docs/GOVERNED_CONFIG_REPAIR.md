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
* MCP_BEARER_TOKEN is the **only** shared trust root for Approval signing
  and encrypted model-candidate storage between API and VM MCP. Both must have the identical, high-entropy token (at least 32 UTF-8
  bytes). The claim HMAC uses a domain-separated key derived from that token
  using HMAC-SHA256 with context
  `aiops/configuration-apply/approval-claim/v1`, not the raw bearer bytes.
  No additional AIOPS_CONFIG_APPLY_SIGNING_SECRET setting is necessary.
  This couples MCP transport authorization, Approval signing and encrypted
  candidate storage: possession of the bearer permits deriving both subkeys. Protect and
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

## Complete-file LLM corrections into the governed change workflow

`service_config_llm_repair` now uses the **complete, verified configuration
file** (not a value-free excerpt) as LLM input **only on an explicit operator
request** and only with `AIOPS_FULL_CONFIG_LLM_ENABLED=true`. Entire file
values, including possible secrets, leave the VM MCP worker for the
**administrator-approved HTTPS/loopback LLM endpoint**. The LLM is not an
execution authority. Configure its data retention and DLP/secret governance
before opting in.

The LLM must return a complete corrected document; a bounded diff policy
rejects large unrelated rewrites and changes to recognizable secret-bearing
lines. The worker encrypts the exact candidate with AES-256-GCM, stores it in
a private volume, and binds it to `(target, service, path, source_sha256,
candidate_sha256)`. **Neither the full source nor candidate is returned to
MCP/API/chat/audit/Cognia.** The incident report contains source/candidate
hashes, the lines changed and a **value-free structural diff** only. Diff
content is intentionally *not* a plaintext reveal of production credentials.

The new `llm_full_file_repair` profile is accepted by the existing Approval
contract **only if the worker reports successful encrypted storage and a
registered isolated validator**. It then enters exactly the existing
`pending_validation` queue. The worker decrypts the bound candidate after
rechecking the live systemd/vendor file identity and original SHA-256, and
the **same root POSIX transaction** performs staging, `nginx -t`, `jq` or
`xmllint`, then separately approved, one-use signed atomic apply, postcheck
and rollback. Approval consumption is preceded by **another isolated
validation** of the same candidate. On source drift, expiration, mismatched
key, unavailable isolation or failed vendor check, refuse; do not fall back
to executing an LLM-suggested command.

### Minimal LLM change policy and downloadable diff

The full-file LLM request is **repair-only**, not a request to reformat,
refactor or optimize application settings. The VM MCP prompt includes the
recorded vendor error and its line when available. A second, independent
deterministic gate rejects more than **three changed lines**, more than
**three non-whitespace syntax character edits**, edits outside three lines of
the vendor diagnostic, unrelated whitespace or line-ending modifications,
value/credential edits, and sensitive-line modifications. It returns an
explicit rejection code; it never quietly accepts a larger rewrite. The
entire revised document remains hash-bound and requires real staged vendor
validation and human approval before any write.

The Incident Command Room displays a **redacted changed-line diff** from
`full_config_llm_repair.redacted_changes`, in preference to an older
deterministic candidate. The **Download diff (.diff)** control exports the
same redacted structural preview as a text attachment from the browser.
When there are more than six changed lines in a historical proposal, the
inline view shows six and the downloaded artifact contains all recorded
bounded changes (up to the pre-existing 12-line report cap).
Neither the view nor the download exposes raw config values, secrets, or
complete plaintext candidate files. The filename and hashes help identify
which proposal the review applies to. This is not a patch meant to be
applied with a shell command; approval binds to the sealed complete file's
SHA-256, not the redacted display.

### Existing MCP bearer; optional candidate directory setting

The VM MCP worker **reuses the existing** `MCP_BEARER_TOKEN`; there is no new
encryption secret or key-generation command. Administrators may optionally
set `AIOPS_CONFIG_CANDIDATE_DIRECTORY` to choose a private local directory.
Both signing and AES-256-GCM encryption require its existing minimum
strength of 32 UTF-8 bytes. The HMAC-SHA256 derived keys have **different
fixed purpose contexts**:

- approval signing: `aiops/configuration-apply/approval-claim/v1`
- stored candidate encryption: `aiops/configuration-candidate/aes-256-gcm/v1`

Neither derived key nor original token is returned to the API, browser, logs
or LLM. They are deterministic across worker restarts so long as the original
bearer remains unchanged. This preserves compatibility with the signing
mechanism already in production and requires **no additional key**.
The pre-existing feature gate `AIOPS_FULL_CONFIG_LLM_ENABLED` still applies;
an explicit authorized SRE request is still required to disclose the full
file to the trusted LLM.

The vault uses the optional `AIOPS_CONFIG_CANDIDATE_DIRECTORY` if provided
in the VM MCP worker's `.env` or process environment, otherwise defaults
to `/var/lib/aiops/config-candidates` on Linux and
\`%ProgramData%\AIOps\config-candidates\` on Windows. Example for a
Windows-hosted VM MCP service:

```env
AIOPS_CONFIG_CANDIDATE_DIRECTORY=D:\aiops-platform-new\config-candidates
```

Use an **exclusive directory for sealed candidates**, not the source-code checkout
`D:\aiops-platform-new` itself. An absolute one-component drive path such as
`D:\candidate-vault` is syntactically valid, but it must still be dedicated
and have verifiable private ACLs. UNC, device, traversal and relative paths
are rejected on Windows. Never set the monitored Linux VM's path here.
Only the dedicated candidate directory is protected; existing parent
folders are not changed. If the selected folder contains unrelated files
and has overly broad permissions, the worker refuses to rewrite its ACL.
The optional setting must reach the VM MCP **worker process environment**,
not only the API process. Restart that worker after changing its environment.

The vault requires a persistent private directory (owner-only 0700/files 0600 on POSIX, strict
service identity/SYSTEM/Administrators ACL on Windows) and fails closed if
permissions or storage availability cannot be verified. The Windows worker
now **automatically applies a protected, inheritance-disabled NTFS DACL**
on its dedicated candidate directory using native Win32 APIs and the
current worker service SID; sealed child files inherit only these private
permissions. No administrator command or new encryption key
is normally required. If the worker cannot create or secure this directory
with its existing Windows permissions, candidate storage remains blocked
rather than bypassing the access check. If the VM MCP runs in a container, the
selected path must be mapped to a private persistent volume; otherwise
pending proposals cannot survive container replacement.

**Security trade-off:** `MCP_BEARER_TOKEN` is a shared root of trust.
Anyone who steals this bearer can derive both the approval-signing key and
candidate-decryption key. Domain separation prevents accidental *cross-use*
but is not defense against compromise of the bearer itself. **Rotating**
`MCP_BEARER_TOKEN` invalidates all previously stored encrypted candidates,
so fresh proposals and Approval are required. Never silently decrypt with
a fallback or an old, unconfigured key. The same existing bearer must remain
consistent between the API and VM MCP; replicas serving the same vault must
use the same current bearer.

**Candidate TTL: 24 hours** from creation, enforced on reads. Stale files
must be cleaned through retention operations; expiry prevents execution,
but does not itself physically erase ciphertext. A rotated MCP bearer invalidates older candidates; create a new proposal
rather than bypassing decryption. Old stateless LLM proposals cannot be approved: run a **new
full-file repair** after deployment so a sealed candidate is generated.
No configuration file is automatically changed when the model responds.

### Current limits / production acceptance

* One selected **complete UTF-8 file** at a time, up to 24 KiB for model
  submission; resulting exact candidate up to 48 KiB. Larger files are
  refused instead of silently truncated.
* Registered protected-apply validators: **Nginx** using the mount-namespace
  vendor check, **JSON** using `jq empty` (syntax only), and **XML**
  using `xmllint --nonet` (syntax only). **JSON/XML passing does not prove
  Java/.NET/Python service-level semantics**. Other vendors, such as
  HAProxy, TOML, INI, YAML, properties or bespoke parsers, remain
  **analysis-only** until tested service-specific validator adapters exist.
* For Nginx, dependencies outside the staged `/etc/nginx` tree may still be
  live read-only dependencies, not a full hermetic snapshot.
* The modified lines are shown in redacted structural form. Full plaintext
  values must not be returned to an incident browser or ordinary audit API.
* No Python installation is required on monitored Linux VMs; Python and
  `cryptography` run on the AIOps VM MCP worker.
* CI tests cover simulated paths. **Windows NTFS, privileged sudo,
  namespace/mount isolation, post-apply behavior, rollback and monitoring
  reconciliation are REAL ENV REQUIRED.** Do not claim Production PASS
  from mocks or an HTTP 200 alone.
