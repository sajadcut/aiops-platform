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
