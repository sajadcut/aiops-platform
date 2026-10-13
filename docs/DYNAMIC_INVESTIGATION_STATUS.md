# Dynamic Investigation — initial governed slice

Status: **feature-flagged, proposal-only**; not production-accepted.

## Why

Previously Cognia was queried before the exact VM MCP failure was known. The
LLM could analyze evidence but could not select a further bounded diagnostic,
and human review ended without a precise operator information request.
An earlier nginx syntax incident demonstrates this gap; the design is
cross-service and is **not** a service-specific recovery runbook.

## Enabled path

Set `AIOPS_DYNAMIC_INVESTIGATION_ENABLED=true` in the **AIOps API/orchestrator**
environment and restart the service. Default is `false` for rollout safety.

After specialist coordination, `DynamicInvestigationPlanner`:

1. Extracts a **verified** current failed configuration validator result or
   another concrete live diagnostic; no LLM statement qualifies as Live Evidence.
2. Performs a **new, targeted** Cognia search using the error details (with
   redaction, bounded payload, the incident's original Cognia subject scope and
   at most two unique queries). Tracks returned source IDs separately from proof.
3. Asks the LLM for at most two choices from a fixed read-only VM diagnostic
   set; validates enum names, drops any write, arbitrary command, target or path.
   If the current EvidenceCollector budget permits, it collects this evidence
   and reruns the specialists. The user does not gain new execution authority.
4. Converts a **confirmed** syntax-check failure to an explicit request for a
   safely sourced current configuration (the last known-good config is
   **optional**). The output is marked `UNVERIFIED` and contains no fabricated
   configuration, diff, validation result, approval or executable write.
5. Audits the stage and publishes it through the existing workflow checkpoint
   and read-only Decision Brief. The Incident Command Room has an independent
   **AI Proposed Fix** panel showing questions, follow-up knowledge, planned
   checks and precise absence of a validated patch. Progress is event-backed;
   no fake ETA.

The LLM is retried once on a truncated/invalid planning response, using a
bounded schema. Even after two failed attempts, the deterministic operator
question remains, rather than claiming no remediation is needed.

## Important limitations / next implementation gates

This slice does **not** provide live secret-safe file reads, agent patch
generation, a vendor-equivalent isolated validator, a patch Diff viewer with
real bytes, operator reply/resume, a Configuration Change Execution Contract or
Rollback. These are prerequisites for a real configuration modification.
The dashboard intentionally has **no Approve/Apply** action for an unverified
proposal. Do not mistake a successful existing `config_validate` for a
successful check on a proposed change.

Before enabling outside sandbox: provision registered read-only file/context
capabilities using tightly scoped resource policies; bind sources by identity,
hash and trust level; implement a sandbox validator and durable proposal
lifecycle, a user-answer API bound to incident state, and a reviewed
configuration-write runbook. Regression coverage must include concurrent
edits, symlinks, includes, secrets, version drift, failure/retry and rollback.
Until those gates are exercised on real staging infrastructure, configuration
repair is **REAL ENV REQUIRED / NOT TESTED**.

## Security invariants

- No LLM-selected VM target, SSH command, absolute path or writable MCP tool.
- Cognia and incident history remain advisory; live validation has precedence.
- No ExecutionRequest is constructed by DynamicInvestigationPlanner.
- Approval, runtime prechecks and verification continue to be handled by the
  existing governed execution boundaries.
- A possible patch cannot be represented as `VALIDATED` without real test
  evidence for those exact bytes and dependencies.
