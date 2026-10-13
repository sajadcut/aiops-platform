# Incident Decision Brief: guarded read-only release

The Decision Brief is available in Dashboard → Incidents → Incident Intelligence → گزارش تصمیم‌گیری. For incidents with a pending Approval it opens by default. The existing Decision, Approval, Evidence, Audit, Execution and Knowledge Review panels remain authoritative.

## Architecture and trust boundaries

- GET /api/v1/incidents/{incident_id}/decision-brief uses the existing read:incident policy and DB readiness check. Historical snapshot listing and exact snapshot reads share this policy; no POST or hidden archive writes are exposed to the browser.
- Version: decision-brief.v1. checkpoint_version, snapshot_id (SHA-256 of the read-only projection) and generated_at support provenance inspection. The snapshot digest is NOT an authorization binding or permission token.
- Reads persisted Incident, Evidence, Finding, WorkflowCheckpoint, Approval, Memory and related KnowledgeReview draft data. It reuses the current deterministic operator-summary logic for RCA/approval interpretation. This endpoint performs no live MCP calls, Cognia searches, workflow actions, LLM requests or translation.
- MCP is classified only when durable records identify the server; nested tool success or failure is checked separately from HTTP status. Persisted EvidenceCollector source observations additionally distinguish unavailable/error/queried/skipped for Zabbix, Prometheus and Elasticsearch without treating an HTTP 200 or empty query as a tool success.
- Cognia retrieval status and documents come only from stored checkpoint state. Retrieved documents without cited source IDs are marked not_verified. Retrieval does not prove causal influence.
- Operational Memory is historical, never current evidence. A cited historical_memory_id does not prove a current RCA.
- Missing/contradictory findings remain visible. RCA, evaluator and agent-agreement confidence are distinct; absent values remain Unknown.
- Bounded report projections use the canonical recursive redaction policy. Raw tool payloads stay in the existing restricted evidence view.
- Freshness warning uses a 15-minute informational threshold, not an execution authorization gate. Mixed-age evidence is marked mixed instead of being called fresh just because one observation is recent. Collection timestamps use source-provided timestamps when available; otherwise a persisted-record timestamp is explicitly labeled.
- Existing Approve, Reject and separately authorized one-time Resume & Execute remain in the Decision panel. The Brief links there without creating any new permission. Cognia Knowledge Review approval is separate. For newly issued approvals, the governed execution boundaries additionally block drift of the recorded decision/evidence inventory before consuming approval authority.
- Browser language toggle persists. Persian/English deterministic narrative is always available. The optional configured-LLM narrative is requested only when the Brief is opened, via a separate read-only endpoint with a 12-second deadline, 10-minute capped cache, bounded redacted prompt and strict citation/section validation. On any timeout, invalid output or model outage it falls back without preventing access to the structured report. The generated prose is advisory only and cannot change the action, approval or evidence. Untranslated source text is labeled as original evidence.
- The Approval panel remains separate. The Brief shows durable non-sensitive binding metadata, but an evidence-snapshot binding is explicitly marked not verified unless an existing authoritative execution gate proves it.

## Windows validation

From repository root in PowerShell with the existing development environment configured:

    python -m pytest -q tests/unit/test_decision_brief.py tests/unit/test_decision_brief_narrative.py tests/unit/test_decision_brief_browser_runtime.py tests/integration/test_decision_brief_ui_api.py
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

- Optional grounded LLM narrative is implemented, but actual Dotin gateway access and semantic accuracy with production Incident data are REAL ENV REQUIRED. Citation identifiers are syntactically validated; this does not independently prove every assertion in generated prose.
- MCP traces without stored server/tool identifiers cannot be classified as successful calls and remain unknown.
- Historical reports are now archived (on newly recorded approval, rejection, execution and verification transitions) to `incident_decision_brief_snapshots`. Existing historical Incidents are not retroactively reconstructed; the table intentionally begins at deployment. The archive is append-only with an UPDATE-blocking database trigger, de-duplication by event/snapshot hash, source redaction and RBAC-protected read endpoints. Incident retention can remove all associated snapshots through FK cascade. Read-only report GETs never write.
- New approval records from Durable Workflow and direct execution API now carry a separate versioned decision/evidence inventory digest. Both supported execution boundaries compare it before consuming approval authority and cancel a drifted approval. Legacy E2E high/critical approvals without this metadata now require a fresh issued approval; separately governed Chatbot approvals and other legacy scopes retain their existing execution-intent and preflight controls, and are shown as Not Verified for snapshot binding. This is not the Brief's own execution authority. Concurrent Evidence/Checkpoint changes are now serialized against final approval claims via PostgreSQL incident-row locks and a recheck of the full decision/evidence digest under that lock; unit and DB integration acceptance cover the lock. Cross-service, live production concurrency acceptance remains REAL ENV REQUIRED.
- Actual production connectivity and browser E2E acceptance are pending.

## راهنمای تست دستی در ویندوز

در PowerShell، پس از تنظیم سرویس‌ها و دسترسی سازمانی معتبر، Dashboard را باز کنید و از بخش Incidents روی یک رخداد در انتظار تأیید بروید. تب «گزارش تصمیم‌گیری» باید خلاصه فارسی و Evidenceهای ذخیره‌شده را نمایش دهد. اگر LLM فعال باشد، درخواست GET مربوط به مسیر narrative با پارامتر lang=fa انجام می‌شود؛ قطع یا خطای مدل نباید صفحه یا کنترل‌های Approval را از کار بیندازد.

برای بررسی API تنها از کلید یا توکن مجاز استفاده کنید. نمونه مسیرها:

    GET /api/v1/incidents/{incident_id}/decision-brief
    GET /api/v1/incidents/{incident_id}/decision-brief/narrative?lang=fa
    GET /api/v1/incidents/{incident_id}/decision-brief/history
    GET /api/v1/incidents/{incident_id}/decision-brief/history/{snapshot_id}

خروجی route دوم صرفاً متن نمایشی است. از خود این پنل نباید درخواست POST برای تأیید یا اجرای عملیات ارسال شود. تأیید انسانی، مصرف یک‌باره مجوز، Resume و Verification همچنان از مسیر فعلی Dashboard → Decision انجام می‌شوند. تست اجرای واقعی روی محیط اشتراکی یا Production بدون سناریوی تأییدشده مجاز نیست.

## پذیرش بندبه‌بند

ماتریس ممیزی تمام بخش‌های پرامت و ۱۸ سناریوی تست، همراه با تفکیک «پیاده‌سازی شده»، «مشروط به داده»، «گپ» و «نیازمند محیط واقعی»، در [INCIDENT_DECISION_BRIEF_ACCEPTANCE_AUDIT_FA.md](INCIDENT_DECISION_BRIEF_ACCEPTANCE_AUDIT_FA.md) ثبت شده است. وضعیت PASS در CI به معنی Production acceptance نیست.

## Historical snapshots and database validation

After deploying the versioned migration, **run Alembic before starting the API**. A migration failure is a deployment blocker; do not silently disable the archive or approval guard. In the Incidents → Decision Brief view select «تاریخچه نسخه‌های قابل ممیزی». Select any immutable snapshot for historical inspection and return to the current report before acting on an approval. Archived snapshots are never execution credentials.

PostgreSQL acceptance uses the existing CI pgvector service:

    RUN_DB_DECISION_HISTORY_TEST=1 python -m pytest -q tests/integration/test_decision_brief_history_db.py

The test exercises real database immutability, incident isolation, snapshot evolution, stale-approval denial and concurrent evidence/checkpoint locking. The test is not a live MCP/Cognia/LLM or production browser acceptance.


## Unknown Operational Guidance (advisory only)

When Incident Live Evidence cannot verify a diagnostic method (for example, no
allowlisted `config_validate` adapter for an application), a VM tool is
unsupported, a specialist fails or reports an explicit evidence gap, the
SignalAware orchestrator consults the configured LLM once for bounded guidance.
The request is redacted, limited to five knowledge gaps and time-limited.
Responses are stored in `state.context.unknown_guidance` and surfaced under
the operator summary and the Decision Brief's missing-evidence section.

The LLM **does not execute or authorize a command**, select an SSH target,
change service identity, install an adapter or claim that a configuration passed.
Advice is marked unverified and is not Live Evidence or a remediation plan.
Production recovery still requires an allowlisted real `config_validate` result
with `supported=true` and `valid=true`, together with the existing runbook,
Decision, Approval and fresh pre-execution verification. If the model is
unavailable or returns malformed output the unknown remains unresolved; the
workflow never assumes success.

For services with an unknown config syntax, the model recommends how an
engineer can identify an official read-only validation procedure. A reviewed,
fixed diagnostic adapter must be implemented before AIOps can perform it.
