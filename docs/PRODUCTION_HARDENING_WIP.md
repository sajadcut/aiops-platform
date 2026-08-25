# Production Hardening Work-in-Progress

This branch tracks repository-level hardening against MASTER.md 2.2.

## Current blockers

- CI test collection fails in GitHub Actions because repository packages are not on PYTHONPATH.
- Operational Memory write-back is not connected to the verification outcome in the E2E workflow.
- Verification must collect live post-execution evidence when possible and keep supplied after_context as a test override.
- Repository-level acceptance must remain separate from external environment validation.

## Acceptance rule

A capability is PASS only when implementation, error handling and repository tests exercise the complete path. External dependencies remain `EXTERNAL VALIDATION REQUIRED` until tested against a controlled environment.
