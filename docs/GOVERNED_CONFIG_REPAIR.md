# Governed configuration changes — production constraints

## Operator workflow

The registered sequence is evidence-bound discovery and vendor diagnostics, read-only redacted Diff, durable pending_validation Approval request, independent candidate staging, human approval, second explicit execution confirmation, one-time approval consume, signed VM MCP command, guarded on-host backup and atomic replacement, independent vendor syntax verification and automatic rollback on post-write failure.

Approval of the request never writes production files. The target VM never needs Python. Original and proposed config bytes are never included in MCP tool responses, database snapshots, incident audit, browser displays or model prompts.

## Supported executable adapter and limitations

Only the deterministic Nginx duplicated-opening-brace fix currently has a guarded apply adapter. It supports regular non-symlink .conf files under /etc/nginx. The validator clones the /etc/nginx tree, uses a private mount namespace to overlay the candidate and runs the vendor nginx -t binary. External references outside this tree are still live read-only dependencies; the API exposes that validation scope.

JSON trailing-comma previews can be produced for verified files belonging to other services, but syntax-valid JSON does not prove runtime semantics. HAProxy, Tomcat, Java, Apache, YAML, JSON and unknown services remain blocked for real writes unless a specialized guarded validator and versioned apply adapter exist. LLM guesses cannot authorize paths, source bytes, shell instructions or production changes.

## VM installation, no Python

Provision the repository's scripts/vm/aiops-config-guard on every authorized Nginx VM at /usr/local/sbin/aiops-config-guard with root:root ownership and mode 0750, through a separately approved privileged provisioning process. Audit its SHA-256, trusted parents and ownership. It needs /usr/sbin/nginx, mount, unshare, flock, openssl, sha256sum, stat, readlink and GNU coreutils. The host must permit private mount namespaces. Failure to meet these requirements prevents advancement to human-approvable status.

Provision /etc/aiops/config-change.key as root:root, mode 0600, with /etc/aiops owned by root and mode 0700. The file content must exactly match the high-entropy AIOPS_CONFIG_APPLY_SIGNING_SECRET environment variable securely injected into BOTH the AIOps API and the VM MCP service. Use at least 32 unpredictable characters. This key is independent of the MCP bearer token and must never be committed, logged or included in shell command arguments. Restart those services after changing their environment.

Delegate sudo -n only for the exact fixed /usr/local/sbin/aiops-config-guard path to the dedicated monitored-VM SSH identity. NEVER allow arbitrary sudo shell, all commands, or general config-write utilities. Root-helper writes additionally require a short-lived, hash-bound HMAC ticket verified against the root-only key.

The guard retains exact-byte originals in /var/lib/aiops/config-backups, mode 0700 for that directory. The customer must establish encrypted storage/retention and secret-disposal practices. The guard automatically restores the original if the post-write vendor check fails. A successful configuration syntax check does not imply the service is running or the endpoint is healthy; service start/restart is a separately approved action.

## Acceptance limits

CI proves API and UI control-state transitions, cryptographic tampering denial, deterministic reconstruction, bash/sh syntax and contract regressions. CI cannot prove a particular target VM has mounted namespaces or sudo privileges. Before Production Ready, test in a disposable Linux VM: true staging, expected correction, changed-hash refusal, expired/forged ticket refusal, ownership/ACL integrity, forced post-write validation failure, rollback and service state. Until then mark REAL ENV REQUIRED, never PASS by assertion alone.
