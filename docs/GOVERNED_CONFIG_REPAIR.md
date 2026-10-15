# Governed configuration changes — production constraints

## Operator workflow

The registered sequence is evidence-bound discovery and vendor diagnostics, read-only redacted Diff, durable pending_validation Approval request, independent candidate staging, human approval, second explicit execution confirmation, one-time approval consume, signed VM MCP command, guarded on-host backup and atomic replacement, independent vendor syntax verification and automatic rollback on post-write failure.

Approval of the request never writes production files. The target VM never needs Python. Original and proposed config bytes are never included in MCP tool responses, database snapshots, incident audit, browser displays or model prompts.

## Supported executable adapter and limitations

The architecture is **service-neutral**: service and file discovery come from verified systemd observations and vendor diagnostics, not from a hardcoded Nginx-only list. The user interface follows the same Diff, technical validation, Approval, Apply, verification and rollback path for every supported repair profile.

Supported guarded repair profiles:

- **Nginx .conf**: deterministic correction of one unexpected duplicated opening brace in the compiler-confirmed file. Stage the complete /etc/nginx tree in a private mount namespace and run nginx -t. External include dependencies may still be live read-only sources.
- **JSON configuration belonging to ANY verified systemd service**, including .NET appsettings.json, Python/Java services, Tomcat custom JSON and unknown application binaries: remove exactly one trailing comma after observing the invalid JSON, reconstruct the identical hash-bound candidate from the live file, then independently check JSON grammar with **jq empty** in the remote guard before and after atomic replacement. The precise guarantee is **syntax-only JSON validation**. It does not validate application schema, semantics, downstream dependencies, service startup or runtime recovery. Lack of jq blocks validation; no Python is required on the VM.

- **XML configuration from any verified systemd service**, including Tomcat server.xml and Java application XML: remove exactly one unmatched trailing closing tag, only when a separately parsed XML candidate is well formed and contains no DTD/entity declarations. The fixed remote guard requires xmllint and runs --nonet --noout before and after atomic replacement. This is **XML syntax only**, not validation of Tomcat semantics or startup.

Unknown service formats such as YAML, properties, INI, HAProxy and Apache vendor syntax still need their own registered deterministic repair and validated action profiles before executable approval. A model cannot generate privileged shell, authorize a file from a guess, or transform unreviewed bytes. Instead, LLM-guided discovery identifies candidate systemd/config paths which are then checked by the read-only MCP workers. The new generic engine scans multiple verified configuration paths instead of stopping at the first readable file.


## VM installation, no Python

Provision the repository's scripts/vm/aiops-config-guard on every authorized VM at /usr/local/sbin/aiops-config-guard with root:root ownership and mode 0750, through a separately approved privileged provisioning process. Audit its SHA-256, trusted parents and ownership. Nginx repair needs /usr/sbin/nginx, mount and unshare. JSON repair needs jq; XML repair needs xmllint (libxml2-utils). Both need flock, openssl, sha256sum, stat, readlink and GNU coreutils. The host must permit private mount namespaces. Failure to meet these requirements prevents advancement to human-approvable status.

Provision /etc/aiops/config-change-verify.pem as a **root-owned Ed25519 public key**, delivered through trusted configuration management. The VM never receives a private signing secret. Generate a secure Ed25519 32-byte private seed and inject its base64 form into AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY on **only the VM MCP service**. Use the matching OpenSSL PEM public key on the VM. Independently inject a high-entropy AIOPS_CONFIG_APPLY_SIGNING_SECRET (at least 32 unpredictable characters) into both the AIOps API and VM MCP for signed MCP authorization. These two signing credentials must be distinct. Never put private keys, HMAC secrets or configuration bytes in Git, shell arguments, logs or audit. Restart those services after changing secure environment values.

Delegate sudo -n only for the exact fixed /usr/local/sbin/aiops-config-guard path to the dedicated monitored-VM SSH identity. NEVER allow arbitrary sudo shell, all commands, or general config-write utilities. Root-helper writes additionally require a short-lived, hash-bound **Ed25519 signature** verified with the root-owned public key; the root VM never receives an API or MCP private key.


### Live VM diagnosis after a blocked validation

The API and VM MCP can be healthy while the target VM fails. In the observed
2026-10-15 incident, `config_change_validate` reached the VM and
`sudo -n /usr/local/sbin/aiops-config-guard validate ...` exited **1**;
this alone does **not** prove an Nginx syntax error. Previously the dashboard
collapsed any nonzero exit into `isolated_vendor_validation_failed`. New
deployments report bounded reason codes plus numeric exit status, and persist
these in the Approval record. Raw stdout/stderr, passwords and file bytes are
not displayed.

On the **monitored VM**, an authorized administrator should independently
confirm the exact provisioned Helper and restricted sudo delegation:

```sh
sudo stat -c '%U:%G %a %n' /usr/local/sbin/aiops-config-guard
sudo sha256sum /usr/local/sbin/aiops-config-guard
sudo visudo -c
sudo -l -U <dedicated-ssh-user>
```

Install the Helper from a trusted audited artifact (not from incident-provided
shell text) and grant NOPASSWD **only** to the dedicated VM identity and
**only** for the immutable root-owned
`/usr/local/sbin/aiops-config-guard` executable. The command
`sudo -n` cannot interactively prompt, and production must never retry it
with a password or general-purpose root shell. Example policy for a
dedicated identity (review against local privilege requirements):

```sudoers
<dedicated-ssh-user> ALL=(root) NOPASSWD: /usr/local/sbin/aiops-config-guard
```

Apply policy only after checking with `visudo -cf` on the proposed
sudoers.d file. For Nginx validate, confirm `unshare -m` and bind-mount
privileges are permitted; do **not** weaken isolation on failure.
The current failure codes distinguish sudo authentication/policy, helper
prerequisites, namespace setup, staged vendor syntax and stale source hashes.
Do not approve or execute the change while validation is blocked.

The guard retains exact-byte originals in /var/lib/aiops/config-backups, mode 0700 for that directory. The customer must establish encrypted storage/retention and secret-disposal practices. The guard automatically restores the original if the post-write vendor check fails. A successful configuration syntax check does not imply the service is running or the endpoint is healthy; service start/restart is a separately approved action.

## Acceptance limits

CI proves API and UI control-state transitions, cryptographic tampering denial, deterministic reconstruction, bash/sh syntax and contract regressions. CI cannot prove a particular target VM has mounted namespaces or sudo privileges. Before Production Ready, test in a disposable Linux VM: true staging, expected correction, changed-hash refusal, expired/forged ticket refusal, ownership/ACL integrity, forced post-write validation failure, rollback and service state. Until then mark REAL ENV REQUIRED, never PASS by assertion alone.
