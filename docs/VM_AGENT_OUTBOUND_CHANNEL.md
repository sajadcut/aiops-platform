# Puppet-style outbound VM MCP agent channel

This is the **agent-initiated** transport: each Linux `vmmcpagent`
establishes one persistent **outbound WSS** session to the AIOps API, then
receives strictly named MCP tasks and returns results over that same session.
No target-side incoming TCP port, SSH, reverse SSH, or local HTTP listener is
used when the connection mode is `outbound`.

## Architecture

```text
Incident / Chatbot -> existing Policy & Human Approval -> VMEdgeMCPClient
    -> VM_EXECUTION_BACKEND=agent_pull
    -> API process-local, authenticated broker
       ^ single outbound WSS connection (TLS server verification + bearer)
       | per-target secret, target identity and expiry checks
    vmmcpagent (mode=outbound) -> original LocalVMConnector / MCP dispatch
       -> allowlisted diagnostics, governed sudo + config guard -> results
```

The old modes remain supported:

- `ssh` — original VM MCP worker uses SSH to reach VMs.
- `agent` — API calls an on-host agent over pinned inbound HTTPS /mcp.
- `agent_pull` — on-host agent calls API outbound over WSS; API forwards
  work only over the authenticated agent's existing session.

## API .env

```env
VM_EXECUTION_BACKEND=agent_pull
VM_AGENT_TOKENS={"10.248.16.82":"<unique-secret-at-least-32-bytes>"}
VM_AGENT_ENDPOINTS={}
SSH_ENABLED=False
```

The API must be reachable at a public/internal **WSS** endpoint with a
properly verified certificate and a reverse proxy that forwards WebSocket
Upgrade. `VM_AGENT_TOKENS` keys are exact target identities; each VM has a
different strong secret. No API-to-VM routes are needed.

**Bootstrap and health:** the API's `/api/v1/health/ready` does not
require connected outbound agents; otherwise readiness-gated ingress would
prevent agents from establishing their first session. Agent connectivity is
still reported independently as `vm_mcp` dependency health and through the
authenticated `GET /api/v1/vm-agents/status` endpoint. Keep disconnected
hosts visible and fail execution closed; do not mark them operationally healthy.

**Write-result integrity:** after a mutable operation has reached an Agent,
loss of the response, a caught local execution exception, a replayed request
ID or an oversized response is reported as `UNKNOWN` and requires an
independent state check. Expired/busy/not-connected requests which never
reached the Agent are `NOT_STARTED`. Cancellation of the HTTP/API task
does not roll back an in-flight VM write. All still-valid request IDs are
retained in the Agent process; on replay-cache saturation new requests are
rejected instead of forgetting IDs that could be replayed.

**Important scaling constraint:** the current broker's sessions and pending
results are **process-local**. For `agent_pull`, deploy one AIOps API worker
and one API instance handling both Agent WebSocket sessions AND requests for
VM execution. Do **not** run multiple Gunicorn workers, multiple API pods or a
non-sticky load-balanced fleet with this backend. Different processes cannot
find each other's sessions. Failures are fail-closed with no SSH fallback.
A distributed broker with durable execution/audit state is a separate
prerequisite to a horizontally scaled production deployment.

Recommended reverse proxy timeout: more than 210 seconds, WebSocket Upgrade
enabled, max message size 1 MiB. Never expose the per-agent token in the URL
or logs.

## Target Linux host /data/aiopsvmagent/agent.env

```env
APP_ENV=production
MCP_SERVER_PROVIDER=vm_agent
MCP_SERVER_REQUIRE_AUTH=True
SSH_ENABLED=False
VM_AGENT_CONNECTION_MODE=outbound
VM_AGENT_CONTROL_PLANE_WS_URL=wss://aiops.example.internal/api/v1/vm-agents/connect
VM_AGENT_CA_BUNDLE_PATH=/etc/ssl/certs/internal-ca.pem
VM_AGENT_TARGET=10.248.16.82
VM_AGENT_ALLOWED_SERVICES='["nginx","gfpapi"]'
VM_AGENT_BEARER_TOKEN=<same-unique-secret-as-this-target-in-API-map>
MCP_BEARER_TOKEN=
AIOPS_CONFIG_CANDIDATE_DIRECTORY=/data/aiopsvmagent/config-candidates
LOG_DIR=/data/aiopsvmagent/logs
```

The URL is an operator-configured **base path**. The agent appends its exact
`VM_AGENT_TARGET` on the wire. It refuses `ws://`, URL credentials, query
tokens, fragments and unknown paths. TLS peer/hostname validation is enabled.
Leave the CA value empty to use the system trust store.

Install with the existing `vmmcpagent/build.sh` and `install.sh`; start
the existing `vmmcpagent.service`. Its entrypoint now selects
`run_outbound_forever()` instead of Uvicorn whenever
`VM_AGENT_CONNECTION_MODE=outbound`. Reconnecting is automatic with bounded
exponential backoff. Heartbeats rely on WebSocket Ping/Pong.

## Security/operational constraints

- Each connection authenticates **before accept**, using that VM's registered
  `VM_AGENT_TOKENS[target]`. Unknown targets, weak tokens and duplicates fail.
- The broker accepts only tools in the original 29-tool VM MCP contract and
  binds `arguments.target` to the authenticated target.
- On-host `_call("vm_agent", tool, args)` still checks service allowlist,
  required identifiers, hash- and signature-bound config approval, and the
  root-owned guard. No arbitrary shell MCP tool is exposed.
- Each request has an unpredictable ID, expires in at most ~190 seconds, and
  is executed at most once **per running agent process**. There is no
  automatic replay/retry of mutable operations after connection loss.
- A missing agent or busy channel **before dispatch** returns `NOT_STARTED`
  for writes; no command was sent. A disconnect, ambiguous timeout or lost
  response **after dispatch** returns `execution_outcome_unknown` for writes;
  independent reconciliation is required before any new operator-approved
  attempt. Reads fail closed. No more than one operation is in flight per VM.
- A restart does not provide durable exactly-once execution history. Do not
  claim distributed transaction guarantees or production parity from unit
  tests alone. Operator approvals are still required upstream.
- For config file apply the isolated vendor validator, signed Root Guard and
  rollback remain the same as the prior VM Agent pathway.

## Acceptance (real environment required)

1. On the Linux VM, block all API-origin VM inbound traffic including port 22;
   permit outbound WSS only. Confirm agent connects.
2. Test all 29 MCP tools, health/status, per-service privileges and systemd.
3. Assert wrong target/token, duplicate connection, expired message, and
   non-allowlisted tool/service are rejected.
4. Test restart during network loss and post-write response loss; require
   unknown result rather than duplicate operation.
5. Validate a signed config repair through the full Approval -> Candidate ->
   independent validation -> Apply/rollback -> UI/audit lifecycle.
6. Verify legacy `ssh` and `agent` modes still operate.
7. Before scaling API horizontally, replace process-local broker with a
   distributed session routing and durable command journal.

The authenticated operator endpoint `GET /api/v1/vm-agents/status` reports
per-host connection state without exposing bearer tokens. Permission
`read:incident` is required.

Unit regressions: `tests/unit/test_vm_outbound_agent.py`. Dedicated CI:
`vm-agent-transport`. These are not substitutes for on-host validation.

## First-connection sudo credentials (per target)

The on-host Agent's `VM_AGENT_EXEC_USERNAME` must be the existing **Linux
account running the systemd service**, not a shell argument or a remote SSH
login. The Agent refuses root and any mismatch between this setting,
`os.geteuid()` and the account sent by the API.

The API keeps the username and password in its **protected API .env** as
requested (readable plain text in that file, **not** exposed in HTTP responses
or audit logs). The API validates credentials by VM target; only after
successfully authenticating the Agent's WSS bearer token does it send one
`credentials` frame. The Agent checks that its configured and actual Unix
user match, installs the password only into **process memory**, and replies
with a password-free `credentials_ack`. The Broker refuses operational
dispatch until this acknowledgement arrives. Reconnections repeat the
bootstrap and discard the previous password.

### API server: example .env

```env
# Other AIOps API variables remain as currently deployed.
VM_EXECUTION_BACKEND=agent_pull
SSH_ENABLED=False
VM_AGENT_ENDPOINTS={}
VM_AGENT_TOKENS='{"10.248.16.82":"replace-with-unique-strong-agent-token-at-least-32-bytes","10.100.6.199":"replace-with-another-unique-agent-token-at-least-32-bytes"}'
VM_AGENT_EXECUTION_CREDENTIALS='{"10.248.16.82":{"username":"opsbot","password":"example-sudo-password-for-vm82"},"10.100.6.199":{"username":"opsrunner","password":"example-different-sudo-password-for-vm199"}}'
```

Each `VM_AGENT_EXECUTION_CREDENTIALS` entry must match a key in
`VM_AGENT_TOKENS`. The example strings are **not real secrets**: replace
every token/password and restrict the API `.env` access. Do not commit it to
Git. This configuration is only used with `agent_pull`, and no SSH password
is needed.

### Destination VM (10.248.16.82): /data/aiopsvmagent/agent.env

```env
MCP_SERVER_PROVIDER=vm_agent
MCP_SERVER_REQUIRE_AUTH=True
SSH_ENABLED=False
VM_AGENT_CONNECTION_MODE=outbound
VM_AGENT_CONTROL_PLANE_WS_URL=wss://aiops.example.internal/api/v1/vm-agents/connect
VM_AGENT_CA_BUNDLE_PATH=/etc/ssl/certs/your-internal-root-ca.pem
VM_AGENT_TARGET=10.248.16.82
VM_AGENT_EXEC_USERNAME=opsbot
VM_AGENT_ALLOWED_SERVICES='["nginx","gfpapi"]'
VM_AGENT_BEARER_TOKEN=replace-with-unique-strong-agent-token-at-least-32-bytes
MCP_BEARER_TOKEN=
AIOPS_CONFIG_CANDIDATE_DIRECTORY=/data/aiopsvmagent/config-candidates
LOG_DIR=/data/aiopsvmagent/logs
```

No Linux password goes in `agent.env`; it is fetched automatically on first
WSS connection. Ensure that `opsbot` exists on the host, that systemd actually
runs as it, and that **its Linux password** matches the API password. After
editing the file, rerun the installer to provision
`/etc/systemd/system/vmmcpagent.service.d/10-execution-user.conf`, then
restart the unit. Restarting a running unit is an administrator's planned
maintenance action, not something performed automatically by API startup.
Changing account ownership for existing sealed config candidates requires
manual migration/reapproval.

### Privilege policy (sudoers)

Install and review `vmmcpagent/sudoers.example` with `visudo`, replacing
`aiops-agent` with the configured Unix username. A scoped
`PASSWD: /usr/bin/systemctl start/restart/reload <allowlisted-service>`
entry and `PASSWD: /usr/local/sbin/aiops-config-guard *` are required for
password-mode privileged operations. The Linux account password is only
supplied to `sudo -k -S` over child stdin, **not** in shell argv, environment,
disk or command-result fields. The fixed root guard still validates
configuration signatures and hashes. Do not grant `NOPASSWD: ALL` or a
generic root shell. A sudoers profile marked NOPASSWD may perform authorized
actions without consuming the provisioned password; use PASSWD if your policy
requires authentication each time.

Credentials are deleted from the Agent's session state upon disconnect, but
Python cannot guarantee cryptographic zeroization of in-memory string copies.
The control-plane password remains in its operator-owned configuration and
process memory by design, so a secret manager or systemd credentials is
preferable when available. Credential delivery requires verified WSS TLS.



## Agent-side TLS switch and dual text/JSON audit

For the destination VM **10.248.16.82**, using API
`10.248.41.67`, configure `/data/aiopsvmagent/agent.env` with:

```env
VM_AGENT_CONTROL_PLANE_WS_URL=wss://10.248.41.67/api/v1/vm-agents/connect
# Recommended, requires CA/hostname or IP SAN
VM_AGENT_TLS_VERIFY=True
VM_AGENT_CA_BUNDLE_PATH=/etc/ssl/certs/internal-ca.pem

LOG_DIR=/data/aiopsvmagent/logs
LOG_LEVEL=INFO
LOG_CONSOLE_ENABLED=True
LOG_TEXT_FILE_ENABLED=True
LOG_JSON_FILE_ENABLED=True
LOG_TEXT_FILE=aiopsvmagent.log
LOG_JSON_FILE=aiopsvmagent.json.log
LOG_ROTATION_MODE=size
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=10
LOG_UTC=True
```

**Exception for a disposable private test environment only**:

```env
VM_AGENT_TLS_VERIFY=False
VM_AGENT_CA_BUNDLE_PATH=
```

This still requires the `wss://` scheme, but it disables validation of the
remote API's TLS certificate and hostname. Since this transport delivers the
per-host Linux sudo password at first connection, a man-in-the-middle can steal
the password or impersonate the control plane. The Agent emits a clear
`vm_agent_tls_peer_verification_disabled` warning. Prefer deploying your
private CA PEM and keeping `VM_AGENT_TLS_VERIFY=True`.

The Agent logs to both
`/data/aiopsvmagent/logs/aiopsvmagent.log` (text)
and `/data/aiopsvmagent/logs/aiopsvmagent.json.log` (JSON lines).

Each application WebSocket request and response generates a separate record
with UTC timestamp, log level, `trace_id` correlated to the command ID,
target, tool, service, status, failure class, frame length and
`response_time_ms`. Every rejected frame, reconnect, transport error,
subprocess start, exit code and timeout is recorded too. Only non-sensitive
**metadata** is logged; full frames, passwords, candidate file bodies,
signed claims and stdout/stderr are intentionally omitted. JSON and text logs
are rotated by size (10 MiB, 10 backups by default). The systemd service's
User must own its `logs` directory (the installer provisions it).

Use `journalctl -u vmmcpagent -f` for console diagnostics. A TCP
handshake or accepted WSS connection is not proof of a valid sudo credential;
test a pre-approved bounded action and independently verify host state.


## TEST ONLY: direct ws://10.248.41.67:80 without TLS or reverse proxy

Unlike WSS/HTTPS, plain WebSocket upgrades disclose HTTP headers, paths and
network metadata. This optional **lab-only** variant uses an independent
32-byte per-target pre-shared key to authenticate both peers and encrypt every
application frame (including the API-delivered Linux sudo password and all
subsequent command/results) with authenticated AES-256-GCM. The initial Bearer
header is visible on the network, but **Bearer possession alone is insufficient
to complete the PSK proof exchange**. Each session derives fresh directional
keys from independent server/client nonces; replayed or tampered frames fail
closed. This custom protocol is not a substitute for standard TLS in production.
Set **APP_ENV=test on both processes** and explicitly enable this mode on both.
Production startup and agent URL validation refuse it.

API .env additions (preserve all other existing AIOps configuration):
```env
APP_ENV=test
VM_EXECUTION_BACKEND=agent_pull
SSH_ENABLED=False
VM_AGENT_ENDPOINTS={}
VM_AGENT_WS_TEST_MODE=True
VM_AGENT_TOKENS='{"10.248.16.82":"REPLACE_WITH_48_RANDOM_OR_LONGER_BEARER"}'
VM_AGENT_WS_TEST_KEYS='{"10.248.16.82":"REPLACE_WITH_EXACTLY_64_RANDOM_HEX_CHARACTERS"}'
VM_AGENT_EXECUTION_CREDENTIALS='{"10.248.16.82":{"username":"szendehnam","password":"REPLACE_WITH_TEST_VM_SUDO_PASSWORD"}}'
```

Agent /data/aiopsvmagent/agent.env additions (keep service allowlist/logging):
```env
APP_ENV=test
MCP_SERVER_PROVIDER=vm_agent
SSH_ENABLED=False
VM_AGENT_CONNECTION_MODE=outbound
VM_AGENT_TARGET=10.248.16.82
VM_AGENT_EXEC_USERNAME=szendehnam
VM_AGENT_CONTROL_PLANE_WS_URL=ws://10.248.41.67:80/api/v1/vm-agents/connect
VM_AGENT_WS_TEST_MODE=True
VM_AGENT_WS_TEST_KEY=REPLACE_WITH_SAME_64_RANDOM_HEX_FROM_API
VM_AGENT_BEARER_TOKEN=REPLACE_WITH_SAME_TARGET_BEARER_FROM_API
VM_AGENT_CA_BUNDLE_PATH=
```

Create secrets separately per target using Python `secrets.token_hex(32)`.
Never put real keys/passwords into Git, sample templates or debug logs. Run
one API worker with Uvicorn **directly** on the Backend test IP:
```powershell
python -m uvicorn apps.api.main:app --host 10.248.41.67 --port 80 --workers 1
```
The WebSocket route is built directly into FastAPI/Uvicorn, so Nginx/reverse
proxy is **not required** in this simple test layout. The API and all its other
endpoints are also reachable via unauthenticated HTTP transport on port 80;
use strict lab VLAN firewall restrictions and never use production passwords
or public-network exposure. Ensure nothing else binds port 80. Production
must use HTTPS/WSS with verified certificates; disable
`VM_AGENT_WS_TEST_MODE` and change the Agent URL to `wss://`.

The Broker is in-process and requires one Uvicorn worker/API replica.
After the service connects, check the authenticated endpoint
`GET http://10.248.41.67:80/api/v1/vm-agents/status` and perform a
read-only `service_status` test. A successful TCP connection alone is
not proof of matching shared keys or provisioned sudo credentials.
