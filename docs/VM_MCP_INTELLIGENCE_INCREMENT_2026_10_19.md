# VM MCP intelligence increment — 2026-10-19

> **Status:** PARTIAL / REVIEW REQUIRED / NOT PRODUCTION READY. The main branch is unchanged.
> This document describes implemented code and remaining acceptance obligations, not live host verification.

## Architecture and trust boundaries

- Natural-language requests are mapped to typed, restricted chatbot intents.
- \`vm_investigate\` is a bounded, read-only diagnostic orchestration on the control plane using **only** registered \`vm_telemetry\` actions through \`ExecutionService\`.
- Evidence flows through the configured VM MCP transport (SSH-backed central MCP, authenticated agent endpoint, or outbound broker). Tool data remains untrusted.
- Incident-room investigation is incident-bound: it uses independently resolved target/service identity. It stores an audit-safe projection without raw journal text. It does **not yet** persist every sub-observation as an independently reassessed incident Evidence row.
- Writes remain routed through the existing approval/execution/verification boundary; the increment does not add a generic shell tool and does not relax permissions.

## New and expanded capabilities

| Capability | Code status | Limitations |
| --- | --- | --- |
| Disk capacity, inode usage, mount, block device and read-only flags | IMPLEMENTED, Linux, optional tools | \`df\`; optional \`lsblk\` and \`findmnt\`; unavailable fields remain unknown. No Windows drive letters, IOPS trends or LVM topology. |
| \`list_services\` / \`search_services\` | IMPLEMENTED, allowlist-scoped Linux systemd | Cannot claim a full host inventory when policy limits service names; no Windows SCM yet. |
| Chatbot deterministic disk/service result rendering | IMPLEMENTED | Correctness depends on a successful, validated live MCP observation. |
| \`vm_investigate\` host performance | PARTIAL, 5 ordered reads | CPU/memory/disk/process/network snapshot; no confirmed temporal causal diagnosis or Prometheus/Zabbix trend fusion. |
| \`vm_investigate\` service start failure | PARTIAL, 6–7 ordered reads | systemd, journal, runtime, process, host metrics, disk; config validation added only when bounded journal signatures support it. No unapproved writes. |
| Same investigation through Incident Room | PARTIAL | Explicit request required, incident target/service bound, raw logs excluded from audit; composite follow-up not yet converted into independent evidence/reassessment per step. |
| MCP tool annotations and \`outputSchema\` | PARTIAL | VM tools advertise schema and read/write annotations. \`disk_status\`, \`list_services\` and \`search_services\` have stricter client-side validation. Other schemas remain broad. |
| MCP \`structuredContent\` | OPT-IN | Legacy 2025-03-26 wire format remains unchanged. Modern content is provided only when compatible 2025-06-18 or 2025-11-25 is configured. No automatic upgrade to the breaking 2026-07-28 stateless protocol. |
| Universal config edit and repair | EXISTING / PARTIAL | Existing candidate/validator/approval code predates this slice; failing full-config CI and real-host verification block release. |
| Windows VM operations | MISSING | Local Agent remains Linux/POSIX-only; no Windows SCM/volume adapter. |
| Verified recovery and Cognia publication | NOT VERIFIED END-TO-END | Must correlate approved execution, application probes, monitoring recovery and human-reviewed knowledge. |

### Diagnostic semantics

- \`success=true\` means at least one tool observation was collected; **not** that a service or application is healthy.
- \`partial=true\` signals one or more unavailable, blocked or timed-out steps.
- \`root_cause_confirmed=false\` and \`application_health_verified=false\` remain explicit.
- All tool selection is allowlisted; no remotely supplied command string is executed.
- Investigation has a hard bound of 7 tool types, 24 seconds per step and 100 seconds overall (not an overall SLA). Failed tools do not become positive health evidence.

### Protocol compatibility

The current deployment default uses \`MCP_PROTOCOL_VERSION=2025-03-26\`, which is preserved. Newer MCP 2026-07-28 removes the legacy initialize/session handshake, so it requires a separate two-sided transport upgrade and conformance suite rather than merely changing an environment value.

Useful background: https://modelcontextprotocol.io/specification/2026-07-28/server/tools and https://modelcontextprotocol.io/specification/2026-07-28/changelog

## Validation status

Latest inspected commit before this documentation: \`0138b593a2b4236c5a97921e8e07f8862076e5b4\`.

- Quality: **FAIL, 28 failed, 2067 passed, 40 skipped**. Baseline main at \`1dd318ef\` also had **28 failed**, so the inspected code tests added no new named failures. Do not interpret this as a green gate.
- Chatbot Acceptance: PASS.
- VM Agent Transport: PASS.
- Container Acceptance: PASS.
- Full-file Config Repair: FAIL (existing failure, unresolved).
- Unit and fixture coverage for disk, block devices, service inventory, structured output, bounded VM investigation and incident projection was added.
- Real VM SSH and outbound agent deployments, production TLS/auth, Windows host, independent application health probe, actual approval/apply/rollback, and monitoring recovery: **REAL ENV REQUIRED / NOT TESTED**.

## Open security and correctness issues

1. Fix the 28 pre-existing Quality failures and the separate full-file repair failures without weakening tests.
2. Complete output schema validation for every tool and add schema-version negotiation tests for both client and server.
3. End-to-end bounded evidence planner across Agent coordination, service dependencies and service identity discovery. Distinguish successful tool transport from verified target/application health.
4. Persist and independently reassess individual sub-observations in Incident Room. Feed only human-approved verified resolutions into Cognia.
5. Complete OS adapters (Windows), broader disk I/O and device inventory, service dependency/port health probes, and multi-timepoint trends.
6. Evaluate the pre-existing config-change PEM signature mechanism for a secure replacement that maintains approval integrity; do not silently remove an authorization boundary.
7. Mandate appropriate TLS and host identity verification in production; development HTTP configuration must not be presented as production safe.
8. Inspect a fresh, attached \`aiopstext.log\` from the target environment; historical logs are insufficient to certify current runtime status.

**Release gate:** no merge/push to main until relevant CI gates are green and required environment tests are recorded as real results.
