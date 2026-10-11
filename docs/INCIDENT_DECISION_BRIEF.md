# Incident Decision Brief: guarded read-only release

The Decision Brief is available in Dashboard → Incidents → Incident Intelligence → گزارش تصمیم‌گیری. For incidents with a pending Approval it opens by default. The existing Decision, Approval, Evidence, Audit, Execution and Knowledge Review panels remain authoritative.

## Architecture and trust boundaries

- GET /api/v1/incidents/{incident_id}/decision-brief uses the existing read:incident policy and DB readiness check.
- Version: decision-brief.v1. checkpoint_version, snapshot_id (SHA-256 of the read-only projection) and generated_at support provenance inspection. The snapshot digest is NOT an authorization binding or permission token.
- Reads persisted Incident, Evidence, Finding, WorkflowCheckpoint, Approval, Memory and related KnowledgeReview draft data. It reuses the current deterministic operator-summary logic for RCA/approval interpretation. This endpoint performs no live MCP calls, Cognia searches, workflow actions, LLM requests or translation.
- MCP is classified only when durable records identify the server; nested tool success or failure is checked separately from HTTP status.
- Cognia retrieval status and documents come only from stored checkpoint state. Retrieved documents without cited source IDs are marked not_verified. Retrieval does not prove causal influence.
- Operational Memory is historical, never current evidence. A cited historical_memory_id does not prove a current RCA.
- Missing/contradictory findings remain visible. RCA, evaluator and agent-agreement confidence are distinct; absent values remain Unknown.
- Bounded report projections use the canonical recursive redaction policy. Raw tool payloads stay in the existing restricted evidence view.
- Freshness warning uses a 15-minute informational threshold, not an execution authorization gate.
- Existing Approve, Reject and separately authorized one-time Resume & Execute remain in the Decision panel. The Brief links there without creating any new permission. Cognia Knowledge Review approval is separate.
- Browser language toggle persists. Persian/English narrative is deterministic fallback; untranslated source text is labeled as original evidence.

## Windows validation

From repository root in PowerShell with the existing development environment configured:

    python -m pytest -q tests/unit/test_decision_brief.py tests/integration/test_decision_brief_ui_api.py
    python -m pytest -q tests
    python -m compileall -q apps tests

Start the stack using the existing repository deployment guide. Open the Dashboard at its configured local port, then select a pending-approval Incident. Verify the Brief opens without new MCP requests or write operations. Inspect the original Evidence, Audit and Decision panels. Use only an authorized disposable test target for real approval and execution.

## Expected acceptance outcomes

| Scenario | Expected |
| --- | --- |
| nginx VM / Cognia / Memory | Independent live evidence, knowledge and historical experience |
| HTTP 200 with failed MCP tool | Failed, not Success |
| Cognia empty / failed / not queried | Distinct retrieval states |
| Cognia retrieved but not cited | Unverified influence |
| Agent conflict and missing evidence | Conflict IDs and missing items shown |
| Stale evidence | Explicit warning; existing execution policy remains in effect |
| Pending high-risk Approval | Human approval and separate Resume |
| Rejected Approval | No execution authorized by this view |
| Verified recovery and matched Knowledge Review draft | Draft link, never automatic publication |
| Missing LLM | Deterministic bilingual narrative |
| Legacy Incident | Unknown where data does not exist |
| Secret-bearing tool response | Redacted projection |

REAL ENV REQUIRED: production Cognia, SSH/VM MCP, Prometheus, Elasticsearch, PostgreSQL/pgvector, OIDC and LLM connectivity; true remediation/rollback, operator approval, browser refresh/resume and operational end-to-end verification. Simulated unit tests must not be reported as a production pass.

## Explicit remaining gaps

- Enhanced narrative generation via the configured LLM, with guarded citations, caching and timeout is not enabled; deterministic fallback is delivered instead.
- MCP traces without stored server/tool identifiers cannot be classified as successful calls and remain unknown.
- No new historical report-snapshot database table; snapshot_id identifies the latest reproducible report projection.
- Plan or evidence rebinding for approval is not implemented by this report; existing execution backend remains the source of truth.
- Actual production connectivity and browser E2E acceptance are pending.
