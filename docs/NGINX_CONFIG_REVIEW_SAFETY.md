# Nginx configuration repair: safe read-only preview (October 2026)

## Why the existing Incident had no repair button

The supplied Incident Room showed a confirmed `nginx -t` failure at
`/etc/nginx/nginx.conf:103` but its investigation proposal said
`needs_read_only_config`, `UNVERIFIED`, and `not_recorded`.
The review probe was gated by the optional dynamic LLM feature and the
previous implementation also invoked target-side `python3`.

## Implemented read-only behavior

- A **confirmed** failed `config_validate` for an identified Nginx
  service triggers `nginx_config_review` and `nginx_config_inspect`
  even when `AIOPS_DYNAMIC_INVESTIGATION_ENABLED=false`.
- The registered VM MCP still accepts **only** an allowlisted service and
  host, selected from the Incident identity; the LLM cannot supply paths.
- The host needs stock shell/coreutils (`readlink`, `stat`, `head`,
  `base64`) only. The remote command refuses symlinks/escaped config
  roots and any file larger than 256 KiB.
- Config bytes are transferred **only over authenticated SSH into the
  trusted VM MCP worker memory**. Python on that worker computes a
  deterministic extra-brace candidate and source/candidate SHA-256
  fingerprints. Raw contents/credentials never enter MCP results, logs,
  evidence tables, browser, Cognia, or LLM prompts. The UI displays only
  sanitized directive names, braces, and line numbers.
- The candidate is explicitly **UNVERIFIED** with
  `stage_failure_reason=isolated_validation_not_available` and
  `validator_executed_on_proposal=false`. Neither `nginx -t` on a
  modified copy nor any production write occurs in this path.
- On existing completed Incidents, the new **ساخت پیش‌نمایش اصلاح با بررسی
  زنده MCP** button invokes the read-only chat probe. Its durable Evidence,
  re-run Agent/Evaluator analysis and recomputed dynamic proposal are saved
  and reloaded in the Incident Room. The button never starts/stops/reloads
  the Nginx service.
- When a candidate and its hashes exist, the operator may submit a
  **review-only** response using the existing RBAC-protected endpoint.
  The response is audit-only; it does not run isolated validation or Apply.

## Why production Apply is still disabled

An end-to-end Apply flow requires independent validation of the exact
candidate and all includes/modules, versioned runbook, encrypted guarded
candidate storage, atomic file-hash-bound replacement, one-time explicit
operator approval, rollback, and post-apply validation and health checks.
**None of those gates is bypassed or claimed by the preview.**
A previous `STAGED_FAILED` result (for example a permission error) is
historical Evidence and does not become success because a new in-memory
candidate can be computed.

## Operational prerequisites

Deploy both the API/orchestrator and VM MCP code, plus the Incident Room
static assets. The SSH identity must have authorized read access to the
specific file; no Python install on monitored hosts is required.
The source file may be unreadable or have a dangerous symlink, in which case
the preview fails closed and the UI must state that no candidate exists.
Live VM/Cognia checks and genuine isolated validation are **REAL ENV REQUIRED**.
