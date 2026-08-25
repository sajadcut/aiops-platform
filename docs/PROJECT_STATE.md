# Project State — AI Ops NeoBankingOperation Platform

**Authority:** `MASTER.md` remains the Single Source of Truth. This file is an implementation-status companion and must not override architectural decisions in MASTER.

**Assessment date:** 2026-08-25

## Executive status

The repository is **substantially implemented and CI-tested**, but it is **not yet fully production-accepted** for a bank/enterprise environment. Repository-level implementation is ahead of the stale Current Status section in `MASTER.md`; external acceptance remains required for real observability endpoints, controlled remediation targets, enterprise identity, HA/DR, backup/restore, signed offline promotion and sustained load/failure behavior.

Current engineering assessment:

- Repository implementation maturity: **~90%**
- Production readiness by code/contract evidence: **~80%**
- External production acceptance: **not complete**
- Current practical phase: **Phase 6 hardening with remaining Phase 4/5/7 gaps**, not Phase 0.

## Implemented and strong

- Python + LangGraph governed workflow.
- PostgreSQL persistence with pgvector and migration acceptance in CI.
- Source-agnostic Signal Gateway for Zabbix, Elasticsearch, Prometheus and canonical operational signals.
- Exact source-event retry idempotency (`source + source_id`).
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

Repository contracts and tests exist for Zabbix, Elasticsearch and Prometheus, but real customer endpoints and metadata conventions still require controlled acceptance. Prometheus now queries common `service`, `service_name` and `app` label conventions, but organization-specific metric naming/service catalog rules remain external configuration concerns.

### Multi-source incident correlation

Exact webhook retries are idempotent. Different source events can carry a supplied `correlation_key`, but automatic cross-source merge policy is not yet production-complete. The platform deliberately does not let an LLM guess that independent Zabbix/Elastic/Prometheus events belong to one Incident because false merges can be operationally dangerous. A deterministic bounded correlation policy/CMDB identity source is still required.

### MCP

Legacy MCP client files exist but are **not the canonical active production integration path**. They use an older HTTP JSON-RPC pattern and currently lack the full authentication/mTLS/capability-governance contract expected for production. Active Evidence collection uses the native governed connector layer. MCP must either be formally hardened/standardized or explicitly deprecated before it can be represented as production-ready.

### Execution coverage

Linux VM SSH is the strongest real execution adapter. Native Windows controlled execution/telemetry, mature Kubernetes write adapters, Ansible/Jenkins integration and VMware integration are incomplete or externally unvalidated. No arbitrary shell/PowerShell should be introduced as a shortcut.

### Verification

The Verification Engine now distinguishes lower-is-better and higher-is-better metrics and refreshes the baseline immediately before execution. Action-specific SLO/verification objectives are still needed for stronger production assurance; generic metric comparison alone is not sufficient for every runbook.

### HA / scale

Two API replicas plus a PDB are not equivalent to proven HA. PostgreSQL HA, distributed worker/queue semantics, distributed rate limiting, backup/restore, disaster recovery, load testing, chaos/failure acceptance and capacity sizing remain incomplete. The current in-process API rate limiter is not a multi-replica distributed control.

### Identity / service-to-service security

OIDC/RBAC is implemented at repository level but real enterprise issuer/JWKS/role mapping needs acceptance. Optional A2A transport has allowlisted origins and HTTPS controls, but cryptographic workload identity/mTLS and rotation are not complete.

### Supply chain / offline production

Offline build now fails closed and runs non-root. Real internal wheelhouse/base-image mirroring, immutable signed image digest promotion and organization registry verification remain external acceptance items.

### Repository governance

`main` is currently unprotected. Required status checks/review policy should be enforced through GitHub branch/ruleset governance. This is a process/control gap rather than an application-code bug.

## Phase assessment against MASTER

| Phase | Assessment | Notes |
|---|---:|---|
| Phase 0 — Foundation & Contracts | 96% | Core contracts, migrations, LLM adapter, tools, Docker and CI exist. Production supply-chain acceptance remains. |
| Phase 1 — Observability & Context | 90% | Connectors, Signal Gateway, Incident/Context and cross-source evidence exist; real endpoint acceptance + deterministic cross-source correlation remain. |
| Phase 2 — LangGraph Intelligence | 95% | Triage, specialist routing, structured outputs, peer context, RCA/Evaluator and bounded evidence refresh implemented. |
| Phase 3 — RAG & Operational Memory | 90% | PostgreSQL+pgvector, governance and separation implemented; corpus/relevance/false-reuse acceptance remains. |
| Phase 4 — Controlled Automation | 84% | Policy/approval/execution/runbook governance strong; adapter breadth, rollback acceptance and real target execution remain. |
| Phase 5 — Verification & Learning | 88% | Fresh baseline, metric-aware verify and governed memory exist; per-action verification objectives and real recovery acceptance remain. |
| Phase 6 — Production Hardening | 78% | OIDC/RBAC, CI, pod hardening and offline contracts exist; HA/DR/backup/distributed limits/workload identity/real acceptance remain. |
| Phase 7 — Scale & Advanced Agents | 76% | Broad agent set exists, but Jenkins/GitLab/VMware/advanced platform integration and scale proof remain incomplete. |

## Known architectural rules

1. Live production Evidence is authoritative.
2. RAG and Operational Memory are auxiliary and separate.
3. Agent/LLM output cannot authorize a write.
4. Asset identity and source-event idempotency are deterministic, not LLM guesses.
5. Write actions go only through Decision/Policy → Approval where required → Execution Service → independent Verification.
6. Peer Agent findings are analysis context, not Evidence.
7. No connector failure may be replaced with synthetic production Evidence.
8. A successful tool call is not a successful Incident resolution until Verification succeeds.

## Next engineering priorities

1. Real controlled Zabbix/Elasticsearch/Prometheus acceptance and metadata mapping.
2. Deterministic cross-source Incident correlation using service/asset/CMDB identity and bounded windows.
3. Windows Edge/WinRM constrained telemetry/execution without arbitrary PowerShell.
4. Kubernetes/Ansible/Jenkins governed execution adapters and rollback acceptance.
5. Action-specific verification objectives/SLO contracts.
6. Distributed rate limiting and multi-instance worker/concurrency model.
7. PostgreSQL HA + tested backup/restore/DR.
8. Enterprise OIDC + service/workload identity/mTLS acceptance.
9. Formal MCP decision: harden to a governed capability transport or retire legacy clients.
10. Signed immutable offline artifact promotion and branch/ruleset protection.

## External acceptance required before strict Production Ready verdict

- Real observability endpoints and representative incident corpus.
- Real LLM endpoint/model performance and failure behavior in restricted network.
- Real remediation targets with least-privilege accounts and rollback drills.
- Before → action → after recovery evidence on reference scenarios.
- Enterprise OIDC/role mapping and internal service identity.
- PostgreSQL HA, backup/restore and disaster-recovery exercise.
- Load/soak/failure/chaos tests at expected incident concurrency.
- Internal registry signing/verification/promotion with immutable digest.
- Security review/red-team of prompt injection, tool abuse, identity and supply chain.

## Verdict

The project should be described as **advanced repository implementation with strong safety boundaries and green CI when verified on the latest HEAD**, not as “all phases complete” or “fully Production Ready”. Strict production acceptance remains gated by the external and distributed-systems checks above.
