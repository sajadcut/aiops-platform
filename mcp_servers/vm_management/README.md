# VM Management MCP Server

Standalone operational boundary for governed VM access.

## Architecture

```text
Agents -> Control Plane -> Decision/Approval -> ExecutionService
                                      |
                                      v
                           VMEdgeMCPClient (HTTP/MCP)
                                      |
                                      v
+----------------------------------------------------------------+
| VM Management MCP Server                                       |
| auth -> session -> tool allow-list -> inventory authorization  |
|                         -> fixed capability handler -> SSH      |
+----------------------------------------------------------------+
                                      |
                                      v
                              Managed Linux VMs
```

The Control Plane never opens SSH sessions and never receives VM credentials. The MCP server does not expose an arbitrary command API.

## Implemented MCP tools

Read-only: `collect_vm_metrics`, `service_status`, `process_snapshot`.

Write: `restart_service`. Writes are disabled by default, require the write bearer token, require a UUID-shaped `approval_id`, and must be explicitly allowed for the target in inventory.

Planned extension points: `service_logs`, `validate_service_config`, `reload_service`, `reboot_vm`, `disk_usage`, `network_status`. These names are recognized by inventory validation but are intentionally not exposed by `tools/list` until handlers exist. `reboot_vm` should remain high-risk and disabled by default when implemented.

## Threat model and boundaries

The server fails closed for unknown targets, unknown tools, unauthorized services, missing credentials, disabled writes, missing/malformed approvals, SSH errors, and timeouts. Target addresses come from inventory; callers cannot turn an arbitrary IP into a managed VM. Service names are validated and must be allow-listed. Remote commands are fixed templates selected by handlers; caller-supplied shell commands are impossible.

VM credentials are referenced indirectly by `credential_ref`; that value names an environment variable containing the private-key path. Tokens, key material and passwords must never be stored in inventory or committed to Git.

Production should keep strict host-key verification enabled and mount a managed `known_hosts` file. The current transport supports key-based OpenSSH only. Password authentication is intentionally excluded.

## MCP lifecycle

Endpoint: `POST /mcp`.

Supported methods: `initialize`, `notifications/initialized`, `tools/list`, `tools/call`. `initialize` returns `Mcp-Session-Id`; subsequent calls require the session until its TTL expires. `DELETE /mcp` releases the session. `GET /health` exposes only component health and whether writes are enabled.

Tool results use both standard text content and `structuredContent`, allowing the existing `MCPClient.json_content()` helper to consume typed results.

## Authentication

Server-side variables:

```env
VM_MCP_SERVER_READ_TOKEN=<read identity>
VM_MCP_SERVER_WRITE_TOKEN=<separate write identity>
```

Control Plane maps to them using its existing configuration:

```env
VM_MCP_URL=http://127.0.0.1:8765/mcp
MCP_BEARER_TOKEN=<same read identity>
MCP_WRITE_BEARER_TOKEN=<same write identity>
MCP_REQUIRE_HTTPS=False
```

Use HTTPS/mTLS or a trusted service mesh in production. Plain HTTP is for isolated local/lab testing only.

## Inventory

Copy `inventory.example.yml` to an untracked deployment-specific `inventory.yml`. Example:

```yaml
vms:
  - id: haproxy-lab-01
    hostname: haproxy-lab-01
    ip: 10.100.6.199
    environment: test
    role: load-balancer
    ssh_user: root
    credential_ref: VM_HAPROXY_LAB_01_SSH_KEY
    allowed_operations: [collect_vm_metrics, service_status, process_snapshot, restart_service]
    allowed_services: [haproxy]
```

Prefer a dedicated non-root automation account with narrowly scoped sudo instead of `root` for production.

## Local Windows / PowerShell lab setup

From the repository root:

```powershell
Copy-Item .\mcp_servers\vm_management\inventory.example.yml .\mcp_servers\vm_management\inventory.yml
$env:VM_MCP_SERVER_INVENTORY_PATH = "mcp_servers/vm_management/inventory.yml"
$env:VM_MCP_SERVER_REQUIRE_AUTH = "true"
$env:VM_MCP_SERVER_READ_TOKEN = "replace-read-token"
$env:VM_MCP_SERVER_WRITE_TOKEN = "replace-write-token"
$env:VM_MCP_SERVER_WRITE_ENABLED = "false"
$env:VM_MCP_SERVER_SSH_STRICT_HOST_KEY_CHECKING = "true"
$env:VM_MCP_SERVER_SSH_KNOWN_HOSTS = "$HOME\.ssh\known_hosts"
$env:VM_HAPROXY_LAB_01_SSH_KEY = "$HOME\.ssh\id_ed25519"
python -m mcp_servers.vm_management
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

Configure/restart the Control Plane:

```powershell
$env:VM_MCP_URL = "http://127.0.0.1:8765/mcp"
$env:MCP_REQUIRE_HTTPS = "false"
$env:MCP_BEARER_TOKEN = "replace-read-token"
$env:MCP_WRITE_BEARER_TOKEN = "replace-write-token"
$env:INTERNAL_API_ROLE = "sre"
uvicorn apps.api.main:app --port 5321
```

Expected startup tools when `VM_MCP_URL` is present: `mock_executor` in non-production plus `ssh_vm` and `vm_telemetry`.

## Read-only HAProxy validation first

Do not enable writes initially. Validate MCP directly through the existing client:

```powershell
python -c "import asyncio; from integrations.vm.mcp_client import VMEdgeMCPClient; async def x():`n c=VMEdgeMCPClient(); print(await c.service_status('10.100.6.199','haproxy')); print(await c.collect_metrics('10.100.6.199')); print(await c.process_snapshot('10.100.6.199')); await c.close()`nasyncio.run(x())"
```

A successful service response contains `success=true`, `tool=service_status` and `data.status.ActiveState`.

Unknown target/service, missing key, host-key mismatch or MCP unavailability must fail without touching the VM.

## High-risk remediation flow

Only after read-only validation, set `VM_MCP_SERVER_WRITE_ENABLED=true` and restart the MCP server. Keep the Control Plane approval flow authoritative:

```text
Signal -> Incident -> Evidence -> RCA -> Decision
 -> high-risk Approval -> approved remediation
 -> ssh_vm/restart_service -> VM MCP -> HAProxy
 -> vm_telemetry verification -> Audit
```

Create remediation through the existing endpoint with exact target/service binding, approve it through the normal approval endpoint, then call `POST /api/v1/approvals/{approval_id}/execute`. The MCP server independently requires its write identity, an allow-listed target/service and a UUID-shaped approval id.

For HAProxy production hardening, add `validate_service_config` and `reload_service` before preferring reload over restart. A future `reboot_vm` handler must require write identity + approval + explicit inventory permission and should have a separate policy/risk gate.

## Docker

Build:

```powershell
docker build -f mcp_servers/vm_management/Dockerfile -t aiops-vm-mcp .
```

Mount inventory, known_hosts and private keys as read-only secrets. Do not bake them into the image.

## Tests

```powershell
pytest -q tests/unit/test_vm_management_mcp.py tests/integration/test_vm_management_mcp_protocol.py
```

The tests use a fake transport and therefore require no real VM.

## Troubleshooting

`vm_target_not_authorized`: target is absent from inventory.

`vm_service_not_authorized`: service is not allow-listed for that VM.

`vm_write_disabled`: server write switch remains false.

`vm_valid_approval_id_required`: write call lacks a UUID-shaped approval id.

`write_identity_required`: read token was used for a write tool.

`vm_credential_not_configured`: the inventory `credential_ref` environment variable is missing.

`vm_ssh_command_timeout`: remote operation exceeded the configured command timeout.
