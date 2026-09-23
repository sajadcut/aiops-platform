# Operational Memory v2 — Governed Incident Learning

## Purpose

Operational Memory is the PostgreSQL + pgvector store for historical operational
experience. It is intentionally separate from Cognia Governed Knowledge RAG and
from current Live Production Evidence.

The core rule is:

**Historical Operational Memory may guide investigation and planning, but it is
not current Evidence and cannot authorize an action.**

## Learning loop

```text
Signal / Incident
  -> Live Evidence
  -> Triage + Specialist Investigation
  -> RCA with uncertainty preserved
  -> Evaluator
  -> Decision / Approval
  -> Governed Execution
  -> Independent Verification
  -> Operational Memory Episode
  -> Retrieval on later incidents
  -> Current Evidence revalidation
  -> Reuse feedback / effectiveness
```

This is retrieval-based operational learning. It is not online model training.

## Memory episode

Each episode preserves:

- incident/service/environment and asset scope
- trigger metadata and normalized symptom pattern
- investigation summary, hypotheses, missing evidence and contradictions
- evidence references/provenance rather than giant raw logs
- root cause text, status and confidence
- actual executed tool/action/target/parameters/runbook
- independent before/after verification
- outcome class and reusable lesson
- embedding metadata and lifecycle/staleness fields
- retrieval/reuse/effectiveness counters

Root-cause status is one of:

- confirmed
- probable
- possible
- unconfirmed
- unknown

A successful remediation never upgrades historical root cause to confirmed by
itself.

## Positive and negative experience

The system can persist both successful and unsuccessful operational outcomes.

Typical outcome classes:

- successful_recovery
- failed_recovery
- partial_recovery
- diagnostic_only
- self_recovered
- false_positive
- execution_blocked

Failed or blocked actions are useful historical warnings. They remain auxiliary
context and are never treated as Evidence.

## Actual remediation

The episode is built from the structured ExecutionRequest / ExecutionResult,
not from the LLM final-plan prose. The stored record can therefore identify the
real tool, action, target, sanitized parameters, service, runbook and execution
result.

## Verification

Verification stores the structured before and after states. Examples include:

- service_active
- port_listening
- tcp_reachable
- config_valid
- resource metrics

Expected post-recovery CPU/memory overhead is distinguished from material
regression.

## Idempotent write-back

Operational Memory write-back is retry/resume safe.

Each structured episode receives a deterministic `episode_fingerprint` derived
from incident identity, governed remediation identity, verification before/after
state and outcome class. Transient Evidence IDs are deliberately excluded so an
evidence refresh does not create a duplicate episode. Secret values are redacted
before the fingerprint is produced.

The application performs a fast pre-check and PostgreSQL enforces a unique
partial index on non-null fingerprints. Therefore:

- a repeated workflow resume with the same operational outcome returns the
  existing Memory ID;
- concurrent workers cannot create duplicate episodes for the same exact
  execution/verification result;
- a materially different execution attempt, approval, target, action or
  verification outcome may create a new episode.

This prevents retry noise from biasing retrieval and reuse-effectiveness metrics.

## Embedding resilience

Persistence is core-first:

```text
Build sanitized episode
  -> Commit core MemoryEntry with embedding_status=pending
  -> Generate canonical embedding
     -> success: embedding_status=ready
     -> failure: embedding_status=failed, core episode remains durable
```

Use `scripts/backfill_memory_embeddings.py` to retry pending/failed vectors
and to rebuild vectors whose provider/model/dimension/document-version no longer
matches the current embedding contract. Until re-embedding completes, those
rows remain available through lexical retrieval but are excluded from vector
similarity.

Development/test may use deterministic embeddings. Production still requires a
real configured embedding provider under the existing fail-closed provider
policy.

## Canonical embedding document

The vector is generated from a stable bounded document containing service,
environment, incident pattern, normalized symptoms, historical RCA status,
contributing factors, actual remediation, verification, outcome and reusable
lesson.

Raw giant logs and credentials are not embedding input.

## Hybrid retrieval

Retrieval uses:

1. a bounded query built from the current incident plus fresh Live Evidence
   symptom fields; raw logs and credential values are not copied into the query
2. structured service/environment/lifecycle filters
3. pgvector cosine similarity only for rows matching the current embedding
   provider/model/dimension/document-version contract
4. PostgreSQL Full Text Search, which remains available if the embedding
   provider is unavailable
5. Reciprocal Rank Fusion plus bounded metadata bonuses

The current incident's own Memory episode is excluded from historical retrieval
to prevent self-reinforcing feedback loops.

Supported retrieval modes:

- SIMILAR_INCIDENT
- RCA_ANALOG
- REMEDIATION_EXPERIENCE

Every returned item is explicitly marked:

```text
HISTORICAL OPERATIONAL EXPERIENCE
safe_as_evidence=false
requires_current_validation=true
```

## Agent use and feedback

Retrieved Memory is projected into a shallow bounded prompt form containing the
historical incident pattern, investigation/RCA summary, uncertainty, actual
remediation, verification and reusable lesson. Raw remediation parameters are
not forwarded to agent prompts.

Agents may cite a retrieved episode only through its exact
`historical_memory_ids` value. The runtime allowlists citations against the
Memory IDs actually retrieved for that incident. Historical Memory IDs are
never accepted as Live Evidence IDs.

`memory_reuse_events` records retrieval/rank/similarity plus later attribution:

- `was_cited_by_agent`: the historical episode materially influenced analysis
- `action_executed`: the current governed action matches the historical action
- `influenced_plan`: both citation and action match are true
- verification outcome/reward

`cited_count` counts explicit agent citations once per target incident even
when the final action differs. `reuse_count`, successful/failed reuse counters
and effectiveness change only for attributed action reuse. Duplicate retrieval
events or retrieval through multiple modes cannot double-reward one Memory
episode for the same incident.

Failed or blocked governed executions are also written back as negative
historical experience. They never resolve the incident. Durable runtime and
signal-aware runtime use the same canonical write-back behavior; the historical
`Learning*` classes remain compatibility aliases only.

## Security and governance

The builder redacts common credential fields and secret-like strings before
persistence and embedding. Raw operational source data remains in the canonical
Evidence/source systems.

The existing execution boundary remains unchanged:

```text
Current Live Evidence
 -> Evaluator
 -> Decision
 -> Approval when required
 -> ExecutionService / governed MCP
 -> independent Verification
```

Operational Memory cannot bypass any of these stages.

## Governed execution learning

Operational Memory write-back is attached to all governed execution paths:
durable incident workflow, direct VM remediation/runbook execution and ChatOps.
Verified successful recovery is promoted only when evidence provenance exists.
Failed, blocked or inconclusive governed attempts are also persisted as negative
experience even when post-action evidence could not be collected, so the next
incident can avoid blindly repeating an unsuccessful action.

Approval authority remains independent of Memory. A durable approval is bound to
the exact incident/tool/action/target/parameters/runbook intent and is consumed
with an atomic PostgreSQL compare-and-set. Only the consume winner may receive a
short-lived process-local execution claim; approval IDs, booleans, Memory entries
or a previously consumed approval cannot recreate that one-shot capability.
The claim is redeemed at the central ExecutionService boundary before any
approval-required tool can execute.

## Production maintenance

Kubernetes release rendering includes two digest-pinned CronJobs that use the
same promoted application image as the API and migration job:

- `aiops-memory-embedding-backfill`: hourly retry/re-embedding for pending,
  failed or embedding-contract-mismatched episodes.
- `aiops-memory-mark-stale`: daily lifecycle transition for aged active
  episodes using `MEMORY_STALE_AFTER_DAYS`.

Both jobs use the same ConfigMap/Secret contract, non-root runtime identity,
read-only root filesystem and `concurrencyPolicy: Forbid`.

After rollout, verify the live database from the promoted application image:

```bash
python scripts/verify_operational_memory.py --limit 10
```

After at least one incident has reached Memory write-back, require a durable
episode:

```bash
python scripts/verify_operational_memory.py --require-entry --limit 10
```

Exit codes:

- `0`: migration head is valid and requested checks passed
- `2`: Alembic head mismatch
- `3`: `--require-entry` was requested but `memory_entries` is still empty

The output includes migration status, lifecycle/embedding health and only
non-secret episode metadata for the latest rows.

## Configuration

```env
MEMORY_HYBRID_RETRIEVAL_ENABLED=True
MEMORY_RETRIEVAL_CANDIDATE_MULTIPLIER=4
MEMORY_RRF_K=60
MEMORY_MAX_EMBEDDING_TEXT_CHARS=12000
MEMORY_REUSE_FEEDBACK_ENABLED=True
MEMORY_STALE_AFTER_DAYS=180
```

## Migration

Alembic revisions:

- `h5e6f7a8b9c0` — Operational Memory v2 schema, reuse events, FTS and HNSW.
- `i6f7a8b9c0d1` — retry/resume-safe episode fingerprint and unique partial index.

Both migrations are additive and preserve existing `memory_entries`. Legacy
rows remain readable; old rows may keep a null episode fingerprint until they
are rewritten as v2 episodes. Existing vectors/search metadata remain intact.

## Acceptance criteria

A repository-level acceptance requires:

- clean Alembic upgrade and upgrade-from-existing DB
- pgvector dimension validation
- episode-builder/redaction tests
- idempotent duplicate-suppression test
- embedding-failure core persistence test
- stale embedding-contract re-embedding test
- lexical retrieval during embedding-provider outage
- current-incident self-exclusion test
- agent Memory citation allowlist and prompt-bounding test
- positive/negative reuse-attribution test
- failed approved execution negative-learning test
- explicit Incident A -> durable Memory -> Incident B retrieval/citation/action-match -> successful reuse feedback acceptance
- explicit Incident C failed-recovery persistence and retrieval as non-evidence negative experience
- full test suite
- security/hygiene checks

Real provider behavior, real production embeddings and operational reuse against
target infrastructure remain REAL ENV REQUIRED.
