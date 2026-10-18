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
VM_AGENT_CA_BUNDLE_PATH=/etc/aiops/agent-ca.pem
SSH_ENABLED=False
# Optional: retain your legacy VM_MCP_URL for switching back to ssh later.
VM_MCP_URL=http://127.0.0.1:9105/mcp
```

`VM_AGENT_ENDPOINTS` is JSON, not comma-separated URLs. Production demands
HTTPS endpoints ending in `/mcp` and a valid peer certificate/hostname.
The optional CA file allows an internal PKI. `MCP_BEARER_TOKEN` must be the
same secret on the Control Plane and selected VM MCP workers: it authenticates
MCP requests and derives the separate config-approval signing key. Provision
it using a secret manager, never commit it to git. Configure the client
certificate/key pair when a mutual TLS gateway requires it.

## Install on each Linux target

Use a dedicated unprivileged Linux service account (for example
`aiops-agent`), with a locally provisioned AIOps package/checkout and
Python virtual environment. No SSH daemon, SSH key or SSH password is needed
by this backend. The currently supplied package uses Python; it is **not**
a separately built single-file native executable.

Example private environment for the agent on the target:

```env
APP_ENV=production
MCP_SERVER_PROVIDER=vm_agent
MCP_SERVER_REQUIRE_AUTH=True
MCP_BEARER_TOKEN=<inject-the-control-plane-secret>
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

Example systemd service:

```ini
[Unit]
Description=AIOps on-host VM agent (no SSH)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aiops-agent
Group=aiops-agent
WorkingDirectory=/opt/aiops
EnvironmentFile=/etc/aiops/agent.env
ExecStart=/opt/aiops/.venv/bin/uvicorn apps.mcp_server.main:app --host 127.0.0.1 --port 9105
Restart=on-failure
RestartSec=5
NoNewPrivileges=no
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

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
