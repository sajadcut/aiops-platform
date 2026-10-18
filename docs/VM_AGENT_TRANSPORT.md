# Agent-based VM execution without SSH

The legacy `VM_MCP_URL` / `MCP_SERVER_PROVIDER=vm` SSH worker remains
unchanged. The alternative is an **on-host** MCP worker:
`MCP_SERVER_PROVIDER=vm_agent`. The API chooses exactly one backend with
`VM_EXECUTION_BACKEND=ssh|agent`.

```text
API / Incident / Chatbot
   -> Evaluator -> Policy -> Approval -> Execution -> Verification
   -> VMEdgeMCPClient (same read/write tool schemas and result contracts)
      | VM_EXECUTION_BACKEND=ssh
      +--> legacy VM MCP worker -> SSH -> allowed destination
      | VM_EXECUTION_BACKEND=agent
      +--> pinned HTTPS endpoint for exact target -> VM agent on target
           -> LocalVMConnector -> fixed local Linux commands / guarded sudo
```

Neither LLM prompts nor alerts select a URL. In agent mode each explicit target
must match a key in `VM_AGENT_ENDPOINTS` **and** the receiving agent's
`VM_AGENT_TARGET`. Unknown targets fail closed. No automatic SSH fallback
occurs when an agent is unreachable.

## Control Plane API configuration

SSH (existing configuration, preserved):

```env
VM_EXECUTION_BACKEND=ssh
VM_MCP_URL=http://127.0.0.1:9105/mcp
SSH_ENABLED=False
```

Agent mode (multiple destination machines):

```env
VM_EXECUTION_BACKEND=agent
VM_AGENT_ENDPOINTS={"10.100.6.199":"https://vm199.example.internal/mcp","10.248.16.82":"https://vm82.example.internal/mcp"}
VM_AGENT_TOKENS={"10.100.6.199":"<vm199-unique-secret-min-32-bytes>","10.248.16.82":"<vm82-different-secret-min-32-bytes>"}
VM_AGENT_CA_BUNDLE_PATH=/etc/aiops/agent-ca.pem
SSH_ENABLED=False
# Optional: retain your legacy VM_MCP_URL for switching back to ssh later.
VM_MCP_URL=http://127.0.0.1:9105/mcp
```

`VM_AGENT_ENDPOINTS` and `VM_AGENT_TOKENS` are JSON maps indexed by the
**same exact target identity**. Production demands HTTPS endpoints ending in
`/mcp`, certificate/hostname verification, and distinct strong secret tokens
for each agent. The optional CA file allows an internal PKI.

Keep the legacy `MCP_BEARER_TOKEN` in the API and original SSH VM MCP
worker. **Do not copy the central MCP_BEARER_TOKEN to any installed agent.**
Instead, provide each agent with only its private `VM_AGENT_BEARER_TOKEN`,
matching the corresponding API map entry. The agent's bounded config-approval
HMAC and encrypted candidate vault derive keys from its own unique token.
Provision all secrets using a secret manager, never commit them to git.
Use a different root-guard Ed25519 signing keypair for each agent/host.
Configure the client certificate/key pair when a mutual TLS gateway requires it.

## Install on each Linux target

Use a dedicated unprivileged Linux service account (for example
`aiops-agent`). No SSH daemon, SSH key or SSH password is needed by this
backend. You can deploy either a Python virtualenv with the AIOps checkout,
or build a **Python-runtime-bundled** `--onedir` executable on a matching
Linux build machine using `vmmcpagent/build.sh` (install the project
requirements and PyInstaller on the build machine). The destination then
needs only the bundled directory and system libraries compatible with the
builder; it does not need a separately installed Python interpreter.
The folder `vmmcpagent/` contains `connector.py`, `__main__.py`,
`agent.env.example`, `vmmcpagent.service`, `aiops-config-guard`,
`sudoers.example`, `build.sh`, `install.sh` and its own README. The
built bundle includes the full **non-secret** Settings baseline at
`/opt/vmmcpagent/.env.example` and the host-specific `agent.env` beside the
binary. The bundle recipe has not been validated on private Linux hosts.

Example private environment for the agent on the target:

```env
APP_ENV=production
MCP_SERVER_PROVIDER=vm_agent
MCP_SERVER_REQUIRE_AUTH=True
# Do not distribute the fleet-wide MCP_BEARER_TOKEN to target machines.
MCP_BEARER_TOKEN=
VM_AGENT_BEARER_TOKEN=<inject-only-this-hosts-unique-secret>
SSH_ENABLED=False
VM_AGENT_TARGET=10.100.6.199
VM_AGENT_ALLOWED_SERVICES=["nginx","haproxy","gfpapi","GFP_Backend"]
AIOPS_CONFIG_CANDIDATE_DIRECTORY=/var/lib/aiops/config-candidates
```

Supply the remaining canonical `.env.example` settings appropriate to this
worker. Set `LLM_*` variables and enable `AIOPS_FULL_CONFIG_LLM_ENABLED`
if full-file repair needs the LLM gateway; agent-host network reachability to
that gateway is then required. Candidate vaults live **on their worker** and
must not be shared across SSH/agent transport switches mid-approval.

Example systemd service **is provided as a file**:
[`vmmcpagent/vmmcpagent.service`](../vmmcpagent/vmmcpagent.service).
It uses `WorkingDirectory=/opt/vmmcpagent`,
`EnvironmentFile=/opt/vmmcpagent/agent.env` (mode 0600, root-owned)
and `ExecStart=/opt/vmmcpagent/vmmcpagent`. For a source-based development
install, run `python -m vmmcpagent` after copying
`vmmcpagent/agent.env.example` to `vmmcpagent/agent.env`.
The secrets remain local to the destination VM, not in the API checkout.

Build and stage the standalone distribution:

```bash
bash vmmcpagent/build.sh
# Copy dist/vmmcpagent/ and vmmcpagent/install.sh to destination VM.
sudo bash vmmcpagent/install.sh /path/to/dist/vmmcpagent
# Fill /opt/vmmcpagent/agent.env, configure host-specific identity and sudoers.
```

### Required privileges and protected configuration APPLY

The **installed-agent** implementation uses the existing, root-owned
`scripts/vm/aiops-config-guard` for `config_change_validate` and
`config_change_apply`. Install the file `vmmcpagent/aiops-config-guard` as
`/usr/local/sbin/aiops-config-guard`
owned by root and not writable by the agent account. It validates allowed
paths/extensions, source/candidate hashes, vendor syntax and rollback; an
approved APPLY additionally verifies an Ed25519 signature using the root-owned
public verification key at `/etc/aiops/config-change-verify.pem`.

The private signing seed, `AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY`, is injected
into the **specific agent worker** by the administrator/secret manager, never
the host root guard. Each VM needs a distinct signing keypair. Without that
seed and the matching public certificate file, configuration APPLY fails closed.
The source/candidate bytes are transported locally over stdin to the fixed
guard, not passed as shell arguments or sent to the Control Plane.

Example installation commands (run only after checking the contents):

```sh
sudo install -o root -g root -m 0750 vmmcpagent/aiops-config-guard /usr/local/sbin/aiops-config-guard
sudo install -d -o root -g root -m 0755 /etc/aiops
sudo install -o root -g root -m 0644 /secure/staged/config-change-verify.pem /etc/aiops/config-change-verify.pem
```

Set narrow sudoers permissions for the fixed helper (which validates every
argument internally), plus explicit `systemctl start/restart/reload <service>`
entries for the approved services. For example, nginx-only operations:

```text
aiops-agent ALL=(root) NOPASSWD: /usr/local/sbin/aiops-config-guard *
aiops-agent ALL=(root) NOPASSWD: /usr/bin/systemctl start nginx, /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx
```

Verify the absolute path of `systemctl` on the destination before configuring
sudoers. The agent may need membership in the host's `systemd-journal`
group to read protected logs. Some vendor `config_validate` fallbacks use
a root-run validator when the service account lacks permission; explicitly
allow the required read-only validator in host policy or report the capability
as unavailable. **Never enable unrestricted `sudo /bin/sh` or
`NOPASSWD: ALL`** for the installed agent.

A root-owned guard is REQUIRED for secure production config APPLY. The
legacy SSH worker retains its existing ephemeral guard behavior; it is not
changed or silently replaced.

The agent HTTP listener is deliberately bound to loopback. Publish it through
a trusted HTTPS reverse proxy with certificate verification (ideally mTLS),
API-origin firewall allowlist and rate limits. Never expose bare Uvicorn or
`/mcp` over unauthenticated public HTTP. Restrict agent file access and
sudoers to explicitly approved service operations and the audited config
guard; do not grant blanket `NOPASSWD: ALL` or a general-purpose root shell.
Existing vendor checks, source-hash compare-and-swap, rollback and
configuration-approval verification are reused from the SSH connector.
Production startup refuses root agent processes and `SSH_ENABLED=True`.

The agent's fixed MCP schema contains exactly the same VM tools as SSH mode:
CPU/memory/disk/network, systemd status and journal, process checks, TCP/DNS/
route/firewall, service/runtime/config discovery, Nginx/JSON/XML inspections,
LLM config candidate generation, independent config validation,
hash/approval-bound apply and approved start/restart/reload. The agent offers
**no arbitrary command RPC**.

## Operational acceptance (REAL ENV REQUIRED)

1. Deploy two agents with distinct `VM_AGENT_TARGET` and service allowlists;
   verify a request to target A cannot be fulfilled by agent B.
2. Confirm exact tool schemas match the SSH VM MCP server, including MCP
   `initialize` server identity.
3. With SSH port 22 closed, compare read-only service/CPU/log/config results
   from agent mode against a baseline for the same target.
4. Try unknown targets, non-allowlisted services, missing bearer token, wrong
   CA, expired approval, and forged config claim: all must be denied.
5. Run an approved restart and independent application/monitor health check.
6. Run config candidate preview and guarded apply with hash-drift/rollback
   acceptance, and verify incident workflow, audit and UI updates.
7. Stop the agent during a write. The API must not silently retry via SSH;
   reconcile ambiguous outcomes against live state before another execution.
8. Flip `VM_EXECUTION_BACKEND` back to `ssh`; the legacy worker must still
   function without data migration.

Repository unit tests validate basic routing and contract behavior. These
are **not** evidence of operational parity or production readiness until
the real-environment checks above pass.


## Exact VM MCP surface coverage

All **29 operations** exist on both MCP providers. The on-host agent inherits
the same bounded diagnostic/parsing logic and the same production-facing result
contract, while replacing SSH transport and the privileged APPLY mechanism.
This is contract/code parity, not proof that any private host has all needed
Linux binaries, permissions or vendor validators installed.

| Area | MCP tools | Agent dependency |
| --- | --- | --- |
| Host and network (13) | `collect_vm_metrics`, `memory_diagnostics`, `host_info`, `disk_status`, `disk_forensics`, `network_status`, `process_snapshot`, `process_status`, `tcp_check`, `port_listener_status`, `dns_check`, `route_check`, `firewall_status` | Linux procfs, coreutils, iproute2, procps and validated target |
| Service evidence (3) | `service_status`, `service_logs`, `system_logs` | systemd/journald and permissions |
| Config and discovery (9) | `config_validate`, `nginx_config_review`, `nginx_config_inspect`, `service_runtime_discovery`, `service_config_discovery`, `service_config_review`, `service_config_llm_repair`, `dotnet_config_syntax`, `config_change_validate` | allowlisted service, vendor validators, locally stored candidate, optional trusted LLM access, root-owned guard for staged validation |
| Governed writes (4) | `start_service`, `restart_service`, `reload_service`, `config_change_apply` | signed/approved intent, per-agent authorization, scoped systemctl sudoers; root guard and Ed25519 public key for config APPLY |

`config_change_apply` supports bounded Nginx/JSON/XML remediation as in the
original worker, **not generic replacement of every arbitrary configuration
file format**. HAProxy or Java-specific configurations may be inspected and
validated when an adapter exists but are not automatically write-capable.
Do not expand the existing APPLY scope merely to make SSH and Agent appear
equivalent. When an LLM proposes a full-file candidate, candidate generation,
validation and APPLY must stay on the same selected worker; changes of backend
during an approval must require rebuilding and reapproval.

Tests: `tests/unit/test_vm_agent_all_tools_parity.py`,
`tests/unit/test_vm_agent_guarded_config.py`,
`tests/unit/test_vm_agent_ambiguous_apply.py`,
`tests/unit/test_vm_local_agent_transport.py`.

Operational results must still be marked **REAL ENV REQUIRED** until real
SSH-disabled VM runs demonstrate all 29 operations with the intended permissions.
