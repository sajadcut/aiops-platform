# Nginx configuration repair: preview, validation, and operator boundary

## Problem reproduced (October 13, 2026)

In an nginx incident, the VM validator reported an unrelated warning
at `/etc/nginx/nginx.conf:43` and an actual fatal `unexpected "{"` at
`/etc/nginx/nginx.conf:103`. The old parser picked the first path/line,
so the Incident Room highlighted 43 instead of 103. Cognia was queried,
but only an advisory asked for the source config; no owned read-only file
review, patch preview, or durable operator response existed.

## Implemented

- `parse_config_diagnostic` selects the fatal diagnostic *first*, then
  determines its file and line. Warning locations never override the fatal.
- When a live `config_validate` result is a supported, confirmed failed
  Nginx check, the opted-in EvidenceCollector obtains `nginx_config_review`
  from the allowlisted VM MCP. This tool accepts **service and target only**:
  the model cannot supply file paths, code or write commands.
- The fixed VM-side program reads at most 256 KiB from a bounded regular
  config file within a verified Nginx config root using no-follow directory
  handles. Only seven sanitized *structural* lines near the error leave the
  VM. Directive arguments and raw config bytes are never returned. The source
  SHA-256 is recorded for future stale-file detection.
- For a narrow, deterministically recognized extra opening brace only, a
  candidate is computed in memory, with a redacted before/after/diff and an
  exact candidate SHA-256. Other syntax faults remain operator review items;
  a guess is not disguised as a fix.
- When an installed Nginx binary permits it, the candidate is checked with
  `nginx -t` on a private temporary copy. The tool removes this copy after
  the test. The result is **STAGED_PASS_NOT_ISOLATED**, **STAGED_FAILED** or
  **UNVERIFIED**. `nginx -t` on a temporary root may still access live
  includes, referenced files and environment! It does NOT prove isolated
  validation, complete service readiness or authorization to apply.
- The Incident Room displays the sanitized current/candidate excerpts, diff,
  line, hashes, validation scope and whether the proposed version was tested.
  It asks the operator whether to request **isolated validation and governed
  review**, or reject. The response is RBAC-guarded (`approve:high_risk`),
  bound to both source/candidate hashes, durable in Audit, and visible after
  page reload. All operator responses are non-executable.

## Unimplemented security-sensitive gates

This change DOES NOT write a production config or create executable Approval.
A complete Apply workflow still needs a real isolated validator covering
the exact candidate *plus includes/modules/version*, a separately registered
configuration-write runbook, encrypted/audited storage for source and proposed
full bytes, decision and file-hash binding, atomic guarded application,
symlink/ownership/permission/SELinux handling, a rollback snapshot,
post-apply `nginx -t`, optional reload/start with separately governed approval,
and independent health verification. Never treat this human review response
as an ExecutionRequest or call `start_service` based on staging alone.

A historical known-good file is OPTIONAL; it may inform Cognia and recovery,
but is not required for syntax diagnosis. A sanitized structural excerpt is
intentionally **not** represented as the complete existing configuration.

## Rollout and testing

The existing `AIOPS_DYNAMIC_INVESTIGATION_ENABLED` flag must be enabled and
both API/orchestrator and VM MCP deployed. The nginx repair preview depends on
Python 3 and a readable Nginx config on the scoped VM. CI tests are mock and
contract tests, not proof on the target VM. Real activation, rootless test
isolation and write/rollback remain **REAL ENV REQUIRED**.
