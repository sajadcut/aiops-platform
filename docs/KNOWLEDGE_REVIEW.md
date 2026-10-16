# Human-approved Cognia Knowledge Review

## Purpose

Turn *verified operational experience* and manually entered runbooks into
Cognia's governed organizational knowledge **only after a human reviewer
approves the exact content**. This is not LLM fine-tuning, not a new Knowledge
RAG store, and never a source of execution approval. Cognia KB #1 remains the
production source of retrieval; PostgreSQL/pgvector remains Operational Memory.

The dashboard provides **Knowledge Review** under the left navigation:
Pending Knowledge queue, Incident/Memory reference, text editor, Approve,
Reject, and Cognia publication/activation status.

## Preconditions

1. Apply Alembic head `k8h9i0j1k2l3` before booting the new API.
2. Configure the private Cognia settings; the known handover uses:
   `COGNIA_BASE_URL=https://cogniaapi.sandpod.ir`,
   `COGNIA_CLIENT_APPLICATION_ID=2`, `COGNIA_KNOWLEDGE_BASE_IDS=[1]`.
   `COGNIA_CLIENT_ID` (string) and `COGNIA_CLIENT_SECRET` come only from
   the deployment secret store. Do not commit/paste their values.
3. The Machine Client must have `kb.contribute` for KB #1. Registration
   authorization alone does not prove processing/activation.
4. Existing Cognia KB approval policy is documented as `none`. **AIOps**
   enforces its own human approval before *any* registration. If Cognia
   later changes to `humanApprovalRequired`, its external human approval
   remains separate and must be completed for activation.
5. For the private API-key UI, `INTERNAL_API_ROLE=sre` allows reviewing and
   publishing. `operator` can create/edit drafts but cannot review/publish.
   Prefer individual OIDC identities for auditable per-person approvals;
   a shared internal API key is recorded as `api-key`, not a person's name.
   Never elevate the general API key solely for convenience.

## Automatic Incident learning (draft only)

AIOps creates a new candidate after its central Operational Memory writer has
recorded a **successful, independently verified, governed remediation**.
The source must have:

- `memory_outcome_class=successful_recovery`
- `verification_result=success` and `verification.status=success`
- `actual_remediation.execution_success=true` with a named action
- An Incident ID and active/validated memory lifecycle
- Exactly one configured destination KB and a numeric Client Application ID

Unverified RCA hypotheses are **not** promoted into confirmed cause claims.
Failed/partial/blocked outcomes remain operational-memory cautionary history,
not automatically successful procedural knowledge; a human can curate
an explicit manual runbook or postmortem draft instead.

The candidate gets a unique `memory_id`; replays of the same incident memory
cannot duplicate the queue. Creation is best effort and never blocks an
Incident's verified operational recovery if Knowledge Review is unavailable.
Older qualifying memories can be entered via the `from-memory` API/UI.

No Cognia POST happens on candidate generation.

## Human review state machine

```text
                         edit (new revision; approval revoked)
pending_review <------------------------------------ approved / publish_failed
     |    |                    ^
     |    +-- reject --> rejected -- edit --+
     |                                      |
     +-- approve [SRE, exact revision and content hash]
                |
             approved
                |
       publish (SRE only, idempotency key)
                |
            publishing -- failure --> publish_failed -- retry --> publishing
                |
             submitted -- activation check --> published
```

Publishing is permitted only if the stored `approved_hash` matches the
content digest and `approved_revision` matches current revision. Every
request re-checks the source memory and configured Cognia KB/scope.
A changed draft must be **reapproved**. A draft cannot edit an in-flight or
already-submitted revision. An `approve` API call alone does NOT publish.

Submission uses `Idempotency-Key: aiops-review-<UUID>-v<revision>`.
A publishing claim is committed before the outbound API call. Concurrent
publish requests are rejected, and a stale claim can be retried only after
three minutes, with the **same idempotency key**, to guard a crash after
Cognia accepted the request. Confirm exactly-once behavior in the real
provider before production acceptance.

HTTP 201/200 from Cognia registration is classified `submitted`, never
`published`. After Cognia processing, `refresh` reads the knowledge's
`activeRevision.revisionId`; only a matching Revision becomes `published`.
No 0-result Search is treated as successful retrieval of the new knowledge.

## API

All endpoints are under `/api/v1`, require authentication, and audit
successful mutations durably without logging knowledge contents or secrets.

| Endpoint | Permission | Purpose |
| --- | --- | --- |
| `GET /knowledge-reviews` | `read:incident` | Queue/filter (limit 100) |
| `GET /knowledge-reviews/{id}` | `read:incident` | Review/decision snapshot |
| `POST /knowledge-reviews/from-memory` | `knowledge:draft` | Pending Incident candidate from verified Memory UUID |
| `POST /knowledge-reviews/manual` | `knowledge:draft` | Manual KB/runbook candidate |
| `PUT /knowledge-reviews/{id}` | `knowledge:draft` | Edit with `expected_revision` |
| `POST /knowledge-reviews/{id}/approve` | `knowledge:review` | Approve exact revision + reason |
| `POST /knowledge-reviews/{id}/reject` | `knowledge:review` | Reject with reason |
| `POST /knowledge-reviews/{id}/publish` | `knowledge:publish` | Publish approved snapshot |
| `POST /knowledge-reviews/{id}/refresh` | `knowledge:publish` | Check active Cognia revision |

The Dashboard Approve & Publish button invokes two distinct API operations.
If Cognia fails, the review remains `publish_failed` and can be retried
without reapproving unchanged content.

## Safety and limitations

- Separate RBAC permissions: `knowledge:draft`, `knowledge:review`,
  `knowledge:publish`. Operational `approve:*` and `execute:*` never
  authorize Cognia publication.
- Read-only retrieval from Cognia and Operational Memory is separate from
  this explicit authorized publishing path.
- Input redaction rejects explicit credentials, authorization headers,
  secrets and embedded tokens; human reviewers MUST still inspect
  sensitive infrastructure identifiers and confidential operational details.
  Automated redaction cannot guarantee every sensitive value is detected.
- The local `knowledge_reviews` table holds drafts, approvals, digest,
  source ID, status and Cognia IDs. **It is not a local Knowledge RAG index.**
  Nothing in it is searchable via RAG until Cognia independently activates it.
- Approval records the API principal. Individual human separation-of-duties
  requires configured OIDC identities; the current shared-key dashboard
  is a single principal and is not proof of two-person review.
- Rejected drafts and published revision history remain auditable; creating
  a new version of an already published Cognia document requires its own
  future reviewed-revision workflow. This initial implementation publishes
  *new* Knowledge registrations, not updates of existing Cognia items.
- Cognia transport currently disables TLS certificate verification in the
  common HTTP client. **Secure transport acceptance is still required**.
- Do not execute the entire Postman collection as a smoke test; its KB
  management and lifecycle operations mutate production state.

## Verification checklist

```powershell
git pull origin main
python -m alembic -c database/migrations/alembic.ini upgrade head
# Restart the AIOps API process; reload /dashboard with Ctrl+F5
```

CI requires unit governance checks and a PostgreSQL integration test of
draft, stale-revision rejection, operator 403, SRE approval, Cognia publishing
with a mocked provider, duplicate prevention and activation confirmation.
Real Cognia acceptance must separately prove KB grant, idempotency
after transport failure, actual processing → activation, and Search retrieval.

**Do not label production end-to-end acceptance PASS before live Cognia
registration/processing/search proof and individual-reviewer identity.**


## Configuration incident diagnosis in Cognia review (2026-10-15)

Previous drafts named `بررسی تکمیلی رخداد nginx` and `Verified incident
recovery: nginx` were overly generic. The follow-up draft used only its most
recent single tool observation, and memory-derived documents did not join the
configuration-change execution audit. Repeated follow-up evidence and memory
episodes could create several indistinguishable pending reviews for one
Incident.

**Current contract:**

- When an incident has an independently observed invalid vendor configuration,
  the review includes the **observed config path, exact error line, classified
  syntax issue and evidence ID**. Only bounded fields from durable
  `vm_mcp` evidence for the *same service* are used. No raw configuration
  contents, secret values, unverified LLM diagnoses, stack traces or journal
  text enter the draft.
- The execution outcome is independently read from an
  `applied_config_vendor_verified` Audit event for that Incident. The dossier
  distinguishes a validated file write from observed systemd activation, and
  from a confirmed source-side Zabbix recovery. **Do not write "incident
  recovered" merely because `nginx -t` passed or the file was applied.**
- The selected-review API includes an `incident_dossier` sourced from that
  Incident's database evidence and Audit. The UI shows the dossier separately
  even for **old, unchanged** reviews, so a reviewer can see config diagnosis
  and the actual outcome before editing/publishing.
- **New** `incident_followup` and verified-memory drafts include a safe
  technical addendum with sourced config details and descriptive titles.
  After a real approved config apply, an additional explicit
  `system:config-apply` draft is created once for that exact approval.
  These candidates are **never auto-approved/published**.
- For older still-untouched, automatically created `pending_review` drafts,
  the operator can choose "افزودن شواهد کانفیگ به پیش‌نویس". This calls
  `POST /api/v1/knowledge-reviews/{id}/refresh-evidence`, increments the
  revision, changes the content hash and leaves the record pending. The
  request rejects reviewed, edited, published, rejected, or otherwise
  non-pristine records; there is no silent migration of approved/published
  bytes.
- Future chat-follow-up requests reuse one existing pending Copilot draft
  per incident. New memory episodes likewise reuse an existing pending
  `incident` draft for that incident. Existing duplicate rows remain
  available for historical review and are not silently deleted or merged.

The knowledge queue is **not** the Cognia knowledge base; only an explicit
human-reviewed, content-hash-bound `publish` operation crosses that boundary.
Any possible reapplication of a historical fix still requires new live
evidence and independent operational Approval.

**REAL ENV REQUIRED:** PostgreSQL data from the nginx incident must be checked
to establish whether the original config-validator evidence and vendor-apply
audit are stored under the same Incident ID. UI preview and pending-review
refresh should then be verified against the actual database, along with
approval immutability and Cognia publication.


## Governed service recovery follow-up drafts (2026-10-15)

AIOps used to persist Operational Memory after an approved Start/Restart but did not create a Knowledge Review candidate. For the gfpapi Restart on 10.248.16.82, execution succeeded and service_active improved (0 to 1), but the required port_listening objective lacked post-execution evidence, so Verification was inconclusive. This must not be labeled verified incident recovery.

Now a completed approved remediation with matching incident-bound audit, live preflight, executed service action, and recorded runbook objective results creates an incident_followup pending_review draft. This draft accurately distinguishes execution success, systemd-active evidence, missing port-listening evidence, unknown RCA, and unconfirmed original alert-source recovery. It is NOT automatically approved or published.

On opening the Knowledge Review UI, one privileged POST /api/v1/knowledge-reviews/reconcile-recent?limit=30 checks the most recent durable remediation_executed events and idempotently backfills missed drafts. GET remains read-only. A deterministic incident+approval review ID survives restarts and human edits. No operational action is re-executed.

A human SRE reviewer must inspect and approve the exact revision, then explicitly publish it to Cognia. The existing strict rule for labeling verified-success Operational Memory as verified incident knowledge remains unchanged.

Cognia /health/ready returning HTTP 500 is a separate outbound readiness/publishing concern: it does not explain an absent local draft. Confirm both local draft creation and actual Cognia acceptance/indexing independently (REAL ENV REQUIRED).


## Complete incident-scenario coverage (2026-10-16)

All **durable** incident outcomes are now candidates for *human* review, not
automatic Cognia knowledge. Previously only verified Operational Memory,
Copilot follow-up evidence, vendor-verified config apply, or audited approved
service recovery could create local review entries. This left no-action,
unresolved, blocked, denied, and failed workflows without reviewable drafts.

A general incident-coverage document uses the incident's own persisted source,
service, alert summary and lifecycle status; bounded evidence IDs and sources;
explicitly marked Agent hypotheses; and incident-bound, vetted technical facts.
It does **not** reuse raw logs/configuration or claim an RCA, remediation or
monitoring recovery from an alert headline. If there is no evidence or no
confirmed recovery, the draft states that gap plainly.

| Durable scenario | Pending reviewer case |
| --- | --- |
| OPEN/ANALYZING; still collecting evidence | Diagnostic case, unverified; decision deferred or rejected by human |
| No-action/observation-only; no runbook proposed | Diagnostic case, no action claimed |
| Evaluator or policy rejected an action | Diagnostic case, not a successful remediation |
| Approval pending/rejected or live preflight blocked | Diagnostic case, no command claimed executed |
| Start/Restart/Reload attempted and failed | Diagnostic case and, where eligible, separately audited execution lesson |
| Command succeeded but port/service verification inconclusive | Diagnostic case and governed partial/inconclusive execution lesson |
| Verified recovery / monitoring resolved | Case with explicitly sourced verification, plus existing verified-memory or runbook case |
| Config diagnostics, candidate-only, or verified config apply | Case plus existing config-specific review with independent apply/recovery evidence |

The canonical analysis runtime creates a best-effort review after the durable
incident commit, including unsuccessful workflows. Creation failures are
isolated from the execution/incident transaction and reported in operational
logs. When an untouched system-owned draft exists, later outcome updates can
refresh it with a new revision and an audit event. A manually edited, rejected,
approved or published case is **never overwritten**.

The Knowledge Review UI now invokes
`POST /api/v1/knowledge-reviews/reconcile-incidents?limit=40&offset=0`
when first opened, in addition to the existing audited recovery reconciliation.
An operator can request additional bounded historical batches (up to 100 at a
time) and load subsequent review queue pages. This allows backfilling older
incidents and viewing reviews beyond the original 100-item display cap.
The API returns matched/scanned, created, existing, failed, next_offset,
has_more and explicit errors; it never silently claims full coverage if KB,
application scope or database writes are unavailable.

The outbox requires `COGNIA_KNOWLEDGE_BASE_IDS` selecting exactly one KB and a
valid `COGNIA_CLIENT_APPLICATION_ID`. Absent configuration is reported as a
drafting error rather than automatically selecting an unauthorized KB.
This historical reconciliation is paginated; a single click does **not**
guarantee that every historical incident in a large installation has already
been processed. It is also possible for new incidents during offset-based
pagination to shift positions; restarting at offset 0 after the pass provides
an idempotent sweep.

Reviewer controls stay distinct: save an edit, approve/reject the pending
local draft, and explicitly publish the approved exact-content revision.
No incident ingestion, reconciliation, or evidence refresh publishes to
Cognia, approves a knowledge record, or authorizes execution.
