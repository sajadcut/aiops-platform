# Governed Runbooks

This directory contains versioned operational runbooks used by the governed
execution plane. A runbook is policy data, not executable free-form automation.
LLM output and API payloads cannot redefine its tool, action allowlist,
preconditions or verification criteria.

## Required contract

Production registry validation is strict. Each runbook must define:

- stable `id` / `name`
- `owner`
- `version`
- positive `timeout`
- `risk`
- `preconditions`
- non-empty actionable `steps`
- `rollback`
- `verification.checks`

Executable runbooks should also define an `execution` contract, for example:

```yaml
execution:
  tool: ssh_vm
  allowed_actions:
    - start_service
    - restart_service
```

When this contract exists, the registered tool is authoritative. A caller cannot
override it with another tool, and the requested action must be explicitly
allowlisted.

## Runtime governance

Static YAML validation is not sufficient to authorize a write.

The production sequence for an executable runbook is:

```text
registered runbook contract
  -> durable approval binding
  -> fresh read-only runtime snapshot
  -> deterministic live precondition validation
  -> one-time approval consume
  -> governed ExecutionService / allowlisted tool
  -> fresh post-action snapshot
  -> registered verification objectives
  -> audit
```

Dynamic facts such as target identity, current service state or configuration
validity cannot be asserted by arbitrary API parameters. They must be obtained
from Live Evidence immediately before execution.

For `vm-service-recovery`, both the normal orchestrated workflow and the direct
runbook execution API reuse `RemediationPlanner.revalidate_execution` for the
fresh precondition check. If the service has already recovered, the action
changed, configuration became unsafe, or required evidence is unavailable, the
write is blocked before approval consumption.

## Verification

A successful tool call is not a successful recovery.

`verification.checks` defines the required post-action objectives. Missing
required objective evidence is fail-closed (`inconclusive`); a failed objective
produces a failed verification. Generic before/after regression semantics remain
active as an additional safety layer.

Example from `vm-service-recovery`:

```yaml
verification:
  window_seconds: 120
  checks:
    - state: service_active
      direction: equals
      expected: true
    - state: port_listening
      direction: equals
      expected: true
```

The workflow uses the registered verification window for fresh evidence
collection. The direct runbook API returns the execution result together with
`precondition`, `verification` and `verified` metadata for executable
runbooks.

## Approval and replay semantics

Approval creation always starts in `pending`. Transition to `approved` is
compare-and-set, bound to the exact incident/tool/action/target/parameters/
timeout/runbook/version/rollback intent, and consumed once at the execution
boundary.

A repeated save cannot resurrect consumed/rejected/expired authority. Source
recovery is rechecked before consume. Process-local runbook replay suppression
is scoped to the same consumed approval; a new approval represents a new
intent and is not incorrectly suppressed.

## Current executable coverage

`vm-service-recovery` is the current fully bound executable runbook. Other
runbooks may describe investigation/rollback/verification policy but must not be
treated as production executable until they receive an explicit execution
contract, a constrained tool adapter, runtime precondition collection and
acceptance tests.
