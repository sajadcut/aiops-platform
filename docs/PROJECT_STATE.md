# Project State — AI Ops NeoBankingOperation Platform

**Authority:** `MASTER.md` remains the Single Source of Truth. This file is an implementation-status companion and must not override architectural decisions in MASTER.

**Assessment date:** 2026-08-26

## Executive status

The repository is **substantially implemented and CI-tested**, but it is **not yet fully production-accepted** for a bank/enterprise environment. Repository-level implementation is well ahead of the historical Current Status section in `MASTER.md`; external acceptance remains required for real observability endpoints, controlled remediation targets, enterprise identity, HA/DR, backup/restore, signed offline promotion and sustained load/failure behavior.

Current engineering assessment after the 2026 external benchmark review:

- Repository implementation maturity: **~91%**
- Production readiness by code/contract evidence: **~81%**
- External production acceptance: **not complete**
- Current practical phase: **Phase 6 hardening with remaining Phase 4/5/7 gaps**, not Phase 0.

## Implemented and strong

- Python + LangGraph governed workflow.
- PostgreSQL persistence with pgvector and migration acceptance in CI.
- Source-agnostic Signal Gateway for Zabbix, Elasticsearch, Prometheus and canonical operational signals.
- Exact source-event retry idempotency (`source + source_id`) with PostgreSQL transaction advisory locking for concurrent retry races.
- Deterministic cross-source Incident correlation for eligible signals using stable service/workload scope, conservative signal families and a bounded time window. LLM/free-text similarity is not merge authority.
- Correlated source events are retained as additional trigger Evidence and related-signal metadata on the same open/analyzing Incident.
- Cross-source Evidence Collector with explicit `queried`, `unavailable`, `error` and `skipped` source observations.
- Deterministic Asset Identity/Context from Zabbix metadata, Prometheus labels, Elastic ECS/Kubernetes metadata and VM telemetry.
- LLM adapter boundary; production startup rejects mock LLM.
- Triage plus specialist agents: application, infrastructure, kubernetes, security, vm, database, network, storage, identity, change, dependency, messaging and recovery.
- Structured multi-agent coordination, bounded handoff, evidence-request rounds and peer operational context. Peer findings remain auxiliary analysis, never live Evidence.
- RCA and mandatory Evaluator gate.
- Deterministic Decision/Policy with concrete execution-request + registered-tool risk binding.
- PostgreSQL-backed approval lifecycle and action/tool/target binding.
- Execution Service with allowlisted tools; agents remain analysis-only.
- Governed Linux VM SSH remediation and read-only VM telemetry.
- Fresh pre-execution Evidence capture and independent before/after Verification.
- Verification uses metric-aware direction semantics; unknown metrics cannot prove recovery.
- Knowledge RAG and Operational Memory remain separate and use PostgreSQL + pgvector.
- Memory write-back requires conclusive outcome and does not replace current Evidence.
- OIDC JWT validation + RBAC/internal API-key fallback.
- Audit persistence and durable application-level workflow checkpoints.
- CI includes full unit/integration/scenario/security suite and PostgreSQL/pgvector migration acceptance.
- Offline container definition is fail-closed for missing dependencies and runs non-root.
- Kubernetes deployment includes rolling-update safety, PDB, resource limits, topology spreading and hardened pod/container security context.

## Partial / not production-accepted

### Observability and context

Repository contracts and tests exist for Zabbix, Elasticsearch and Prometheus, but real customer endpoints and metadata conventions still require controlled acceptance. Organization-specific service catalogs, CMDB identifiers and metric naming remain external integration work.

### Multi-source incident correlation

The deterministic bounded correlation layer is now implemented and race-guarded for one PostgreSQL cluster. It intentionally correlates only known operational signal families and open/analyzing Incidents. It is not yet production-accepted against real alert corpora; CMDB/service-catalog identity and false-merge/false-split measurement remain required. A later correlated signal is attached to an existing Incident/checkpoint, but automatic full workflow re-analysis on every late signal is deliberately not enabled until concurrency and state-transition semantics are acceptance-tested.

### MCP

Legacy MCP client files are now explicitly **deprecated/non-production** and are not the canonical active production integration path. They predate the current MCP OAuth 2.1/resource-audience authorization model. Active Evidence collection continues through native governed connectors. ADR-015 defines MCP as a selected capability transport only: a future production MCP adapter must add Protected Resource Metadata, audience-bound tokens, authorization scopes, workload identity/mTLS, capability allowlists and Audit without bypassing Tool Registry/Policy/Approval.

### Agent deployment

ADR-016 sets a hybrid target: reasoning/LLM/RCA/Policy remain centralized; optional constrained Edge Runtime may run near Linux/Windows hosts or as a Kubernetes DaemonSet for node-local visibility/actuation. Per-host/per-Pod LLM agents are not the target. The Edge Runtime itself is not yet implemented/accepted.

### Execution coverage

Linux VM SSH is the strongest real execution adapter. Native Windows controlled execution/telemetry, mature Kubernetes write adapters, Ansible/Jenkins integration and VMware integration are incomplete or externally unvalidated. No arbitrary shell/PowerShell should be introduced as a shortcut.

### Verification

The Verification Engine distinguishes lower-is-better and higher-is-better metrics and refreshes the baseline immediately before execution. Action-specific SLO/verification objectives are still needed; generic metric comparison alone is not sufficient for every runbook.

### HA / scale

Two API replicas plus a PDB are not equivalent to proven HA. PostgreSQL HA, distributed worker/queue semantics, distributed rate limiting, backup/restore, disaster recovery, load testing, chaos/failure acceptance and capacity sizing remain incomplete. The current in-process API rate limiter is not a multi-replica distributed control.

### Identity / service-to-service security

OIDC/RBAC is implemented at repository level but real enterprise issuer/JWKS/role mapping needs acceptance. Optional A2A transport has allowlisted origins and HTTPS controls, but cryptographic workload identity/mTLS and rotation are not complete. SPIFFE/SPIRE is a reference pattern, not yet an implementation dependency.

### AI-platform observability

Agent telemetry exists but is process-local. The external 2026 benchmark highlights OpenTelemetry GenAI semantic conventions for model/tool spans, token usage and latency. Full OTel export/tracing with sensitive-content controls remains a gap.

### Supply chain / offline production

Offline build fails closed and runs non-root. Real internal wheelhouse/base-image mirroring, immutable signed image digest promotion and organization registry verification remain external acceptance items.

### Repository governance

`main` has been observed as unprotected. Required status checks/review policy should be enforced through GitHub branch/ruleset governance. This is a process/control gap rather than an application-code bug.

## Phase assessment against MASTER

| Phase | Assessment | Notes |
|---|---:|---|
| Phase 0 — Foundation & Contracts | 96% | Core contracts, migrations, LLM adapter, tools, Docker and CI exist. Production supply-chain acceptance remains. |
| Phase 1 — Observability & Context | 93% | Connectors, source observations, Signal Gateway, asset identity and bounded cross-source correlation exist; real endpoint/CMDB/correlation acceptance remains. |
| Phase 2 — LangGraph Intelligence | 95% | Triage, specialist routing, structured outputs, peer context, RCA/Evaluator and bounded evidence refresh implemented. |
| Phase 3 — RAG & Operational Memory | 90% | PostgreSQL+pgvector, governance and separation implemented; corpus/relevance/false-reuse acceptance remains. |
| Phase 4 — Controlled Automation | 84% | Policy/approval/execution/runbook governance strong; adapter breadth, rollback acceptance and real target execution remain. |
| Phase 5 — Verification & Learning | 88% | Fresh baseline, metric-aware verify and governed memory exist; per-action objectives and real recovery acceptance remain. |
| Phase 6 — Production Hardening | 79% | OIDC/RBAC, CI, pod hardening, correlation race locks and offline contracts exist; HA/DR/distributed controls/workload identity/OTel remain. |
| Phase 7 — Scale & Advanced Agents | 77% | Broad agent set and hybrid deployment target exist, but Edge runtime, Jenkins/GitLab/VMware and scale proof remain incomplete. |

## Known architectural rules

1. Live production Evidence is authoritative.
2. RAG and Operational Memory are auxiliary and separate.
3. Agent/LLM output cannot authorize a write.
4. Asset identity, source-event idempotency and Incident correlation are deterministic, not LLM guesses.
5. Write actions go only through Decision/Policy → Approval where required → Execution Service → independent Verification.
6. Peer Agent findings are analysis context, not Evidence.
7. No connector failure may be replaced with synthetic production Evidence or interpreted as zero anomalies.
8. A successful tool call is not a successful Incident resolution until Verification succeeds.
9. MCP is not itself an authorization boundary and cannot bypass platform governance.
10. Central reasoning plus constrained optional Edge Runtime is the target deployment model.

## Next engineering priorities

1. Real controlled Zabbix/Elasticsearch/Prometheus acceptance and metadata/CMDB mapping.
2. Correlation corpus tests measuring false merge/split rates and late-signal re-analysis policy.
3. Windows Edge/WinRM constrained telemetry/execution without arbitrary PowerShell.
4. Action-specific verification objectives/SLO contracts.
5. Kubernetes/Ansible/Jenkins governed execution adapters and rollback acceptance.
6. Distributed worker/queue/backpressure architecture after benchmark/load evidence and ADR decision.
7. Distributed rate limiting.
8. PostgreSQL HA + tested backup/restore/PITR/DR.
9. Enterprise OIDC + short-lived service/workload identity/mTLS acceptance.
10. OpenTelemetry GenAI/agent/tool observability with sensitive-content controls.
11. Governed modern MCP adapter only for selected integrations, or eventual deletion of legacy compatibility clients.
12. Signed immutable offline artifact promotion and branch/ruleset protection.

## External acceptance required before strict Production Ready verdict

- Real observability endpoints and representative multi-source incident corpus.
- Real LLM endpoint/model performance and failure behavior in restricted network.
- Real remediation targets with least-privilege accounts and rollback drills.
- Before → action → after recovery evidence on reference scenarios.
- Enterprise OIDC/role mapping and internal service identity.
- PostgreSQL HA, backup/restore and disaster-recovery exercise.
- Load/soak/failure/chaos tests at expected incident concurrency, including 500 concurrent Incident admission behavior.
- Internal registry signing/verification/promotion with immutable digest.
- Security review/red-team of prompt injection, MCP/tool abuse, identity, memory and supply chain.

## Verdict

The project is an **advanced governed AIOps implementation with strong evidence and execution boundaries**. It is not “all phases complete” and not yet strict Production Ready. The largest remaining gap has shifted from Agent functionality toward distributed-systems engineering, workload identity, Windows/adapter breadth, action-specific verification and real operational acceptance.
