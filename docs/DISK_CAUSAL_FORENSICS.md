# Evidence-driven disk-pressure remediation

## Rule
Disk usage or inode alerts are symptoms, not evidence that files should be
deleted. Before any removal recommendation, identify the exact file, verified
producer, reason for growth, current activity, retention/backup/legal-hold
requirements, user impact, and a narrowly scoped safe recovery procedure.

## Live diagnostic workflow
1. Read current target mount and inode pressure from Zabbix and VM MCP disk_status.
2. At 90% or higher, ask VM MCP disk_forensics for bounded read-only large-file
   metadata. It searches no more than two pressured mounts and limits scans.
3. The VM tool optionally performs two read-only size observations about
   two seconds apart and a bounded lsof inspection of open file handles. A
   writable handle is evidence of a process holding the file, NOT proof that
   this process caused its historical growth. A short sample with no growth
   does not establish that the file has stopped growing.
4. Compare file modification times, current observed growth and open handles
   with the existing Elasticsearch error observations and Zabbix alert
   chronology. Time proximity is a hypothesis, not a causal conclusion.
5. Treat co-occurrence as a hypothesis, not proof of the process that produced
   the file or of causation.
5. Seek stronger evidence of process ownership, growth trend, error/retry loops,
   log rotation, business/data retention policy and open handles.
6. Ask the LLM for read-only investigation guidance when methods or causes are
   unknown. LLM advice is never Live Evidence or a runtime permission.
7. Prefer fixing the producer/retry storm or rotation failure first, then check
   freed capacity and confirm the original symptom does not recur.

## Deletion and Approval safety
- Do not propose cleanup merely because a file is old or large.
- A file listing or Elastic/Zabbix error observed around the same time is not
  sufficient causal evidence.
- There is NO file-delete MCP tool and no file-delete Execution Service action.
  StorageAgent removes LLM-generated mutating cleanup instructions from its
  recommended actions.
- A future cleanup action must have a separately reviewed, file-specific
  Runbook with the exact immutable path/target binding, cause evidence,
  retention and legal-hold decision, an independent Approval, fresh validation,
  rollback constraints and post-execution verification. Do not bypass these
  steps with a generic Approval.
- A file inventory is intentionally partial and must not be presented as a
  complete filesystem scan or a verified growth measurement.

## Acceptance coverage
Tests: test_disk_causal_forensics.py, test_storage_reliability_engine.py,
test_mcp_server_contract.py, test_vm_diagnostic_evidence.py and
test_incident_command_room.py.

Production validation still requires authorized staging VM access and actual
Zabbix/Elastic event correlation; code review alone is NOT TESTED.


## Multi-finding incident actions (2026-10-16)

A Service Down incident can independently contain a valid configuration repair
candidate, systemd crash-loop evidence, and a full filesystem. The incident
Decision Brief's `remediation_opportunities` is a separate, evidence-bound
**catalog**, not a single action proposal or an executable Approval. The
Incident Room now displays every eligible item and its individual route and
blocker. A hash-bound configuration Approval cannot authorize rotating,
truncating or deleting logs, nor can a Service Start Approval authorize
filesystems changes.

For example, incident `e9bf28f6-fefc-4a03-9142-a9cc6b30b079`
records `/var/log` at 100% with about 20,480 bytes available. Its
large `syslog`/`daemon.log` files are a **read-only inventory**, with
the actual writer, log retention, open-file state and impact still
unverified. The disk opportunity therefore remains
`executor_unavailable`; the UI offers further bounded investigation
instead of pretending it can perform a root-level cleanup. This is
deliberate until a narrow runbook and governed execution tool exist.

Separately, the configuration ticket was independently validated but
its APPLY returned a transport error (`BrokenPipeError`, no remote exit
code). A lost SSH stdin/response does not establish whether the remote
guard wrote anything. The trusted worker now reports
`config_apply_result_unknown`, preserves
`production_write_performed=null`, classifies a safe failure code,
and does not allow auto-reissuing the consumed approval until the live
file hash is read and a new candidate/approval is established.
