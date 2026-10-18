# vmmcpagent — SSH-free VM MCP agent

This directory contains the **installed, on-target** VM execution agent.
The existing VM MCP SSH backend is intentionally retained. The API selects
`VM_EXECUTION_BACKEND=ssh` or `VM_EXECUTION_BACKEND=agent`.

## Files

| File | Purpose |
| --- | --- |
| `connector.py` | Local Linux execution transport; retains the same bounded 29-tool MCP contract |
| `__main__.py` | Agent entrypoint, reads colocated `agent.env`, serves MCP on loopback |
| `agent.env.example` | Agent-specific configuration template; copy to `agent.env` |
| `vmmcpagent.service` | systemd unit for the bundled Linux binary |
| `aiops-config-guard` | Root-owned fixed command for signed configuration validation and APPLY |
| `build.sh` | PyInstaller Linux bundle, no target-side Python installation |
| `install.sh` | Installs bundle/config/service (does not auto-enable or configure sudoers) |

The built Linux directory `dist/vmmcpagent/` also contains the shared,
**non-secret** `.env.example` baseline needed by the existing AIOps
configuration schema. Operator-owned secrets live **only** in `agent.env`,
next to the agent executable. Do not commit that file.

## Build on Linux

From the repository checkout (builder has Python 3.12, project dependencies
and PyInstaller installed):

```bash
bash vmmcpagent/build.sh
```

Copy `dist/vmmcpagent/` and the installer onto the destination, and run
`sudo bash vmmcpagent/install.sh /path/to/dist/vmmcpagent`. The installer
creates `/opt/vmmcpagent/agent.env` mode `0600` if absent and **does not**
enable the service. Before starting, provide `VM_AGENT_TARGET`, per-host
`VM_AGENT_BEARER_TOKEN`, and the service allowlist in that config. The
`aiops-agent` system user/group must already exist. Configure the public
verification key at `/etc/aiops/config-change-verify.pem`, and a **distinct**
Ed25519 private signing key for this VM, before enabling approved config APPLY.

Next, configure **narrow** sudoers only for approved `systemctl` actions and
`/usr/local/sbin/aiops-config-guard`. The root guard validates arguments,
hashes and signed claims; never grant `sudo /bin/sh` or `NOPASSWD: ALL`.
Root guard validation can require `jq`, `xmllint` or `nginx` and
`unshare` depending on profile.

The MCP HTTP listener binds **only** `127.0.0.1:9105` (port configurable).
Publish to the API exclusively through a trusted HTTPS reverse proxy that
validates client identity/firewalls as appropriate. Restrict source hosts and
enable certificate verification. An agent never opens SSH.

Start after configuring and reviewing:

```bash
sudo systemctl enable --now vmmcpagent
sudo systemctl status vmmcpagent
```

## Control Plane switch

```env
VM_EXECUTION_BACKEND=agent
VM_AGENT_ENDPOINTS={"10.248.16.82":"https://vm82.example.internal/mcp"}
VM_AGENT_TOKENS={"10.248.16.82":"<different-random-secret-for-that-host>"}
VM_AGENT_CA_BUNDLE_PATH=/etc/aiops/agent-ca.pem
```

To use the original SSH worker, set `VM_EXECUTION_BACKEND=ssh` and use
the existing `VM_MCP_URL`. There is **no automatic SSH fallback**.

## Compatibility and validation

The MCP tool schemas are the same for both providers. The agent's local
connector is defined here and re-exported from
`integrations/vm/local_agent_connector.py` for backwards compatibility.
Run `tests/unit/test_vm_agent_all_tools_parity.py` and the dedicated
`vm-agent-transport` GitHub Action. Actual privileged service execution
and vendor config validation on a Linux VM remain **REAL ENV REQUIRED**.
For the full security and acceptance guide, see
`docs/VM_AGENT_TRANSPORT.md`.
