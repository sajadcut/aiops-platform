# VM CPU Remediation Flow

For a Linux VM CPU saturation incident:

```text
Zabbix / Prometheus
       ↓
Incident API
       ↓
Context + live Evidence
       ↓
VM Agent + other specialized agents
       ↓
RCA → Evaluator → Decision
       ↓
Remediation Request
       ↓
PostgreSQL Approval
       ↓
ssh_vm / restart_service
       ↓
vm_telemetry / collect_vm_metrics
       ↓
CPU threshold verification
       ↓
Audit + Operational Memory
```

## Configuration

Enable the governed VM execution boundary through the central configuration:

```env
SSH_ENABLED=True
SSH_USERNAME=aiops
SSH_PRIVATE_KEY_PATH=/secure/path/aiops_ed25519
SSH_KNOWN_HOSTS=/secure/path/known_hosts
SSH_STRICT_HOST_KEY_CHECKING=True
SSH_PORT=22
SSH_CONNECT_TIMEOUT=10
VM_CPU_RECOVERY_THRESHOLD=70
```

Never place passwords or private keys in the repository. Prefer a dedicated service account with narrowly scoped `sudo` permissions. The execution adapter does not accept arbitrary shell commands; its write operation is limited to the allow-listed `restart_service` action.

## API flow

Create remediation request:

`POST /api/v1/incidents/{incident_id}/remediation-requests`

Approve:

`POST /api/v1/approvals/{approval_id}/approve`

Execute approved remediation:

`POST /api/v1/approvals/{approval_id}/execute`

Verify CPU recovery:

`POST /api/v1/approvals/{approval_id}/verify`

The verification endpoint is read-only and uses `vm_telemetry` to collect CPU metrics. A remediation is considered verified when measured CPU is at or below the supplied threshold.
