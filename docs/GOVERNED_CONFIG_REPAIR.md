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
* AIOPS_CONFIG_APPLY_SIGNING_SECRET (high entropy, min 32 characters) remains
  mandatory in API and VM MCP. AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY is no
  longer needed by the helperless runtime and no public key file must be
  deployed to the target. Legacy scripts/vm/aiops-config-guard and
  scripts/vm/Install-AIOpsConfigGuard.ps1 are not execution dependencies.

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


## 2026-10-15 execution blocker: missing signing secret

A real approval can reach `approved` after an isolated vendor check and still
fail at `POST /api/v1/approvals/{approval_id}/execute-config` with HTTP 503
`config_signing_key_not_configured`. This is a **control-plane signing-key
precondition**, not a VM syntax failure, and does **not** consume the approval
in the current API implementation.

- Configure `AIOPS_CONFIG_APPLY_SIGNING_SECRET` with a new high-entropy secret
  (minimum 32 characters) in the **API process** and **VM MCP process**.
  The two processes must receive the **identical** value, independently of
  MCP authentication tokens. Use a secrets manager or locked-down deployment
  secret; never commit or log the value.
- Restart/redeploy both processes to pick up configuration. The Settings
  contract loads a local `.env` for development, and explicitly injected
  process environment values override it. Production should use a managed
  secret, not a checked-in file.
- The Incident configuration-review response now exposes a **non-secret**
  `execution_prerequisites.api_signing_key` value of `configured` or
  `missing`. `vm_mcp_signing_key` and `signing_key_match` remain
  `not_checked` unless independently verified; an API-side check cannot
  assert remote readiness.
- Confirm the current Approval still has `approved` status and that the
  original/candidate hashes and the live file have not changed. Then use the
  existing explicit execution action. Never manually bypass the signing gate.

Example for **Windows PowerShell development**, in **each** process-launching
terminal, using one secret created and stored securely out of band:

```powershell
$env:AIOPS_CONFIG_APPLY_SIGNING_SECRET = (Get-Content 'C:\secure\aiops-apply-signing-secret.txt' -Raw).Trim()
# Then launch API or VM MCP from this same terminal.
```

The referenced file must be ACL-restricted to the service identity; the
example path is only illustrative. For a Windows service or CI deployment,
set the secret through the service's secure environment/secret injection,
not via an interactive session that the service does not inherit.

A passing candidate check, an `approved` Approval and a non-consumed grant
must be shown separately in the dashboard. Do not show `PASS` for signing
readiness merely because the vendor validator passed.
