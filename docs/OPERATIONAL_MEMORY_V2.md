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
state, evidence references and outcome class. Secret values are redacted before
the fingerprint is produced.

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

Use `scripts/backfill_memory_embeddings.py` to retry pending/failed vectors.

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

1. structured filters
2. pgvector cosine similarity
3. PostgreSQL Full Text Search
4. Reciprocal Rank Fusion plus bounded metadata bonuses

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

## Feedback

`memory_reuse_events` records retrieval/rank/similarity and whether the same
historical action was later executed and verified. Memory effectiveness is
updated from verified reuse outcomes; it does not change execution authority.

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

## Configuration

```env
MEMORY_HYBRID_RETRIEVAL_ENABLED=True
MEMORY_RETRIEVAL_CANDIDATE_MULTIPLIER=4
MEMORY_RRF_K=60
MEMORY_MAX_EMBEDDING_TEXT_CHARS=12000
MEMORY_REUSE_FEEDBACK_ENABLED=True
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
- embedding-failure core persistence test
- full test suite
- security/hygiene checks

Real provider behavior, real production embeddings and operational reuse against
target infrastructure remain REAL ENV REQUIRED.
