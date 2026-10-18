# vmmcpagent — SSH-free VM MCP agent (Puppet-style outbound WSS supported)

This directory contains the **installed, on-target** VM execution agent.
In outbound mode, set `VM_AGENT_EXEC_USERNAME` in the target's
`/data/aiopsvmagent/agent.env`. It must name the actual existing Linux
account that the Agent's systemd service runs as. The installer generates a
root-owned `10-execution-user.conf` drop-in; rerun the installer and restart
the unit after changing that username. Provision the username/password on
the API **only** through `VM_AGENT_EXECUTION_CREDENTIALS` keyed by the same
`VM_AGENT_TARGET` as `VM_AGENT_TOKENS`. The API delivers it on the initial
authenticated WSS connection and the Agent retains the password only in
memory for scoped password-required sudo actions. No password belongs in
`agent.env`. See [configuration examples](../docs/VM_AGENT_OUTBOUND_CHANNEL.md).

The existing VM MCP SSH backend is intentionally retained. The API selects
`VM_EXECUTION_BACKEND=ssh`, `agent` (inbound HTTPS) or `agent_pull` (Puppet-style
outbound persistent WebSocket). The on-host template defaults to outbound mode.

## Files

| File | Purpose |
| --- | --- |
| `connector.py` | Local Linux execution transport; retains the same bounded 29-tool MCP contract |
| `__main__.py` | Agent entrypoint, reads colocated `agent.env`, serves MCP on loopback |
| `agent.env.example` | Agent-specific configuration template; copy to `agent.env` |
| `vmmcpagent.service` | systemd unit for the bundled Linux binary |
| `sudoers.example` | Reviewed, narrow local sudoers policy example |
| `aiops-config-guard` | Root-owned fixed command for signed configuration validation and APPLY |
| `build.sh` | PyInstaller Linux bundle, no target-side Python installation |
| `install.sh` | Installs bundle/config/service (does not auto-enable or configure sudoers) |

The built Linux directory `dist/vmmcpagent/` also contains the shared,
**non-secret** `.env.example` baseline needed by the existing AIOps
configuration schema. Operator-owned secrets live **only** in `agent.env`,
next to the agent executable. The installed agent defaults to
`/data/aiopsvmagent/` for binary, settings, encrypted config candidates and
logs. Do not commit the private settings file. Root-owned security helpers
and verification keys remain in their system locations.

## Run directly from a source checkout

Copy `vmmcpagent/agent.env.example` to `vmmcpagent/agent.env`, edit the
target, bearer token and allowlist, restrict its mode to 0600, then run
`python -m vmmcpagent` from the repository virtual environment. The built
standalone bundle is recommended for production installations.

## Build on Linux

From the repository checkout (builder has Python 3.12, project dependencies
and PyInstaller installed):

```bash
bash vmmcpagent/build.sh
```

Copy `dist/vmmcpagent/` and the installer onto the destination, and run
`sudo bash vmmcpagent/install.sh /path/to/dist/vmmcpagent`. The installer
creates `/data/aiopsvmagent/agent.env` mode `0600` if absent,
provisions `/data/aiopsvmagent/config-candidates` and
`/data/aiopsvmagent/logs` owned by `aiops-agent` with mode `0700`,
and **does not** enable the service. Before starting, provide `VM_AGENT_TARGET`, per-host
`VM_AGENT_BEARER_TOKEN`, and the service allowlist in that config. The
`aiops-agent` system user/group must already exist. Configure the public
verification key at `/etc/aiops/config-change-verify.pem`, and a **distinct**
Ed25519 private signing key for this VM, before enabling approved config APPLY.

Next, review `sudoers.example` and configure **narrow** sudoers only for approved `systemctl` actions and
`/usr/local/sbin/aiops-config-guard`. The root guard validates arguments,
hashes and signed claims; never grant `sudo /bin/sh` or `NOPASSWD: ALL`.
Root guard validation can require `jq`, `xmllint` or `nginx` and
`unshare` depending on profile.

In the default **outbound** mode the Agent opens **no HTTP listener** and
connects to the central API using outbound WSS. Its configuration must set
`VM_AGENT_CONTROL_PLANE_WS_URL` and it uses its per-host bearer as the
Authorization header, never as a URL query parameter. Details and operational
constraints: [`docs/VM_AGENT_OUTBOUND_CHANNEL.md`](../docs/VM_AGENT_OUTBOUND_CHANNEL.md).

Only in explicit `VM_AGENT_CONNECTION_MODE=inbound` does the MCP HTTP listener
bind **only** `127.0.0.1:9105` (port configurable).
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

For outbound (no open VM port) configure API
`VM_EXECUTION_BACKEND=agent_pull`, its `VM_AGENT_TOKENS` target map, and
`VM_AGENT_ENDPOINTS={}`. Inspect connected hosts through the authenticated
API route `GET /api/v1/vm-agents/status` (requires `read:incident`).

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
