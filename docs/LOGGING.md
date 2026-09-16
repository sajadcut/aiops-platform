# Incident RID and hourly log rotation

## Stable Incident RID

Every canonical Incident log event includes both:

- `incident_id`: the durable Incident UUID.
- `rid`: a stable correlation identifier derived from that UUID.

For UUID-backed Incidents the RID format is:

```text
rid_<32 lowercase UUID hex characters>
```

The RID is deterministic, so it stays identical across API requests,
worker/process boundaries and restarts. No extra database column is required.

The logging processor keeps Incident correlation in a `ContextVar`. Once a
canonical workflow event includes `incident_id`, subsequent structlog and
stdlib log events in the same asyncio execution context inherit both
`incident_id` and `rid`. HTTP transaction logs also calculate the RID from an
Incident path, request body or response body when available. Requests with an
Incident UUID in their path return `X-RID` as a response header.

To inspect one Incident, use:

```bash
python scripts/trace_incident_logs.py \
  8e6e8fca-5ce5-4e1f-9d46-c998142b3fa5 \
  --log-dir /var/log/aiops
```

The same command accepts an RID directly and reads active logs, numbered
rotations and gzip-compressed logrotate archives.

A plain grep also works for active/uncompressed files:

```bash
grep -F 'rid_8e6e8fca5ce54e1f9d46c998142b3fa5' /var/log/aiops/aiops*.log*
```

## Hourly logrotate

Host/VM deployments can install the tracked logrotate policy:

```bash
sudo install -m 0644 deployment/logrotate/aiops-platform /etc/logrotate.d/aiops-platform
sudo install -m 0644 deployment/systemd/aiops-logrotate.service /etc/systemd/system/aiops-logrotate.service
sudo install -m 0644 deployment/systemd/aiops-logrotate.timer /etc/systemd/system/aiops-logrotate.timer
sudo systemctl daemon-reload
sudo systemctl enable --now aiops-logrotate.timer
```

The policy rotates `aiops.log` and `aiops.json.log` every hour, retains 168
rotations (seven days at hourly cadence), compresses old generations and
uses `copytruncate` so the running non-root Python process does not need a
signal/restart or permission to reopen a newly-created file.

`hourly` in a logrotate policy only controls eligibility. The included
systemd timer is what guarantees logrotate itself is invoked every hour.

Kubernetes production currently logs to stdout/stderr with file logging
disabled in the deployment manifest, so host logrotate is intentionally for
file-backed VM/bare-metal/container-volume deployments. Cluster log retention
remains the responsibility of the Kubernetes logging backend.

The application also supports its existing Python size/time rotation modes.
On a host where this logrotate timer is enabled, keep the Python thresholds
as a secondary safety limit; `copytruncate` avoids descriptor handoff issues.
