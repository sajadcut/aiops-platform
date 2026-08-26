# Project State — AI Ops NeoBankingOperation Platform

**Authority:** `MASTER.md` remains the Single Source of Truth. This file is an implementation-status companion and must not override architectural decisions in MASTER.

**Assessment date:** 2026-08-26

## Executive status

The repository is substantially implemented and CI-tested, but it is not yet fully production-accepted for a bank/enterprise environment. External acceptance remains required for real MCP-backed observability servers, controlled remediation targets, enterprise identity, HA/DR, backup/restore, signed offline promotion and sustained load/failure behavior.

Current engineering assessment:

- Repository implementation maturity: ~91%
- Production readiness by code/contract evidence: ~81%
- External production acceptance: not complete
- Current practical phase: Phase 6 hardening with remaining Phase 4/5/7 gaps

## Implemented and strong

- Python + LangGraph governed workflow.
- PostgreSQL persistence with pgvector and migration acceptance in CI.
- Source-agnostic Signal Gateway and deterministic bounded cross-source correlation.
- Cross-source Evidence Collector with explicit `queried`, `unavailable`, `error` and `skipped` source observations.
- Deterministic Asset Identity/Context.
- Triage plus specialist agents with peer context, coordination, RCA and mandatory Evaluator gate.
- Decision/Policy/Approval/Execution separation; Agents remain analysis-only.
- Fresh pre-execution Evidence capture and independent before/after Verification.
- Knowledge RAG and Operational Memory remain separate and use PostgreSQL + pgvector.
- OIDC/RBAC, Audit, durable workflow checkpoints and hardened CI/deployment contracts.
- Repository-wide Python import/dependency integrity validation.

## Canonical MCP external-tool boundary

ADR-015 now defines **MCP as the mandatory Control-Plane transport for every external operational tool**. The active ContextBuilder instantiates `ZabbixMCPClient`, `ElasticsearchMCPClient`, `PrometheusMCPClient`, optional `KubernetesMCPClient`, and optional `VMEdgeMCPClient`. The Control Plane no longer instantiates direct Zabbix/Elastic/Prometheus/SSH connectors for operational Evidence.

The execution-side VM tool keeps its historical registry name `ssh_vm` for runbook/approval backward compatibility, but its connector is now `VMEdgeMCPClient`; the Control Plane no longer opens SSH itself. Direct SSH/WinRM may exist only behind the Edge/MCP Server inside the destination trust zone.

Production MCP controls implemented in repository contracts include:

- protocol-version pinning (`2026-07-28` baseline),
- `Mcp-Method` / `Mcp-Name` HTTP routing metadata,
- HTTPS enforcement in Production,
- bearer identity and/or mTLS client certificate support,
- client-side tool allowlists,
- bounded timeouts,
- no Agent access to raw MCP clients,
- write authority remaining behind Tool Registry → Policy → Approval → Execution → Audit.

Native direct connectors remain only as MCP server-side adapters, migration/test utilities or isolated development fixtures. They are not the canonical Control-Plane path.

## Partial / not production-accepted

### MCP servers and external integrations

The Control-Plane MCP client boundary is implemented, but real Zabbix/Elasticsearch/Prometheus/Kubernetes/VM MCP Servers are external deployment components and still require controlled acceptance in the target restricted network. Their tool schemas, server-side authorization, downstream credentials, audit export and HA must be validated against the actual environment.

### Multi-source incident correlation

Deterministic bounded correlation is implemented and race-guarded for PostgreSQL. It still requires real corpus measurements for false-merge/false-split behavior and CMDB/service-catalog authority.

### Agent deployment

The target remains hybrid: reasoning/LLM/RCA/Policy centralized; constrained Edge Runtime near Linux/Windows/Kubernetes where local visibility/actuation is needed. Per-host/per-Pod LLM agents are not the target.

### Execution coverage

VM execution is now MCP-backed, but real Edge MCP Server implementation/acceptance and Windows constrained actions remain incomplete. Kubernetes/Ansible/Jenkins/DB/network governed write adapters also remain partial.

### Verification

Fresh before/after Verification exists. Action-specific SLO/verification objectives still need full runtime binding for every runbook.

### HA / scale

PostgreSQL HA, distributed worker/queue semantics, distributed rate limiting, backup/restore, DR, load/soak and chaos acceptance remain incomplete.

### Identity / service-to-service security

OIDC/RBAC exists at repository level. MCP supports bearer and mTLS configuration, but short-lived workload identity issuance/rotation and organization PKI integration are not yet externally accepted.

### AI-platform observability

Agent telemetry exists but full OpenTelemetry GenAI/Agent/Tool tracing is incomplete.

### Supply chain / offline production

Offline build is fail-closed and non-root. Real internal wheelhouse/base-image mirroring and immutable signed promotion remain external acceptance items.

## Phase assessment against MASTER

| Phase | Assessment | Notes |
|---|---:|---|
| Phase 0 — Foundation & Contracts | 96% | Core contracts, migrations, tool boundary, Docker and CI exist. |
| Phase 1 — Observability & Context | 93% | MCP-backed source clients, source observations, Signal Gateway, identity and correlation exist; real MCP server acceptance remains. |
| Phase 2 — LangGraph Intelligence | 95% | Triage, specialists, peer context, RCA/Evaluator and evidence refresh implemented. |
| Phase 3 — RAG & Operational Memory | 90% | PostgreSQL+pgvector and governance implemented; corpus acceptance remains. |
| Phase 4 — Controlled Automation | 85% | Policy/approval/execution strong; MCP-backed VM path exists; adapter breadth/real target acceptance remain. |
| Phase 5 — Verification & Learning | 88% | Fresh baseline and governed memory exist; per-action objectives incomplete. |
| Phase 6 — Production Hardening | 80% | MCP external boundary, OIDC/RBAC, CI and pod hardening exist; HA/DR/distributed controls/workload identity/OTel remain. |
| Phase 7 — Scale & Advanced Agents | 77% | Broad Agent set and hybrid target exist; Edge server breadth and scale proof remain incomplete. |

## Known architectural rules

1. Live Production Evidence is authoritative.
2. RAG and Operational Memory are auxiliary and separate.
3. Agent/LLM output cannot authorize a write.
4. Asset identity, event idempotency and Incident correlation are deterministic.
5. Every external operational tool connection from the Control Plane uses MCP.
6. Agent requests canonical Evidence/capabilities; it never receives a raw MCP client.
7. Write actions go through Decision/Policy → Approval where required → Execution Service → MCP → independent Verification.
8. Peer Agent findings are analysis context, not Evidence.
9. Connector/MCP failure cannot be interpreted as zero anomalies.
10. Native direct connectors are server-side/test adapters, not the Control-Plane production path.

## Next engineering priorities

1. Implement/deploy production MCP Servers for Zabbix, Elasticsearch and Prometheus and validate real payloads.
2. Define versioned MCP tool schemas and capability manifests for every external system.
3. Integrate enterprise workload identity/mTLS certificate issuance/rotation for MCP.
4. Build Windows Edge MCP Server with constrained JEA/WinRM/PowerShell actions and no arbitrary PowerShell.
5. Build Kubernetes MCP Server write capabilities behind Execution/Approval and retain read-only Evidence tools.
6. Bind per-runbook verification objectives to Execution receipts.
7. Add correlation corpus acceptance and CMDB/service catalog authority.
8. Decide distributed queue/workers/backpressure after load evidence.
9. Add distributed rate limiting and 500-concurrent-Incident load/soak tests.
10. PostgreSQL HA + backup/restore/PITR/DR.
11. OpenTelemetry GenAI/Agent/MCP/tool tracing.
12. Signed immutable offline artifact promotion and branch/ruleset protection.

## External acceptance required before strict Production Ready verdict

- Real MCP Servers and downstream Zabbix/Elastic/Prometheus/K8s/VM endpoints.
- Real tool-schema compatibility and source metadata conventions.
- Enterprise MCP identity/mTLS and server-side authorization.
- Real remediation targets with least privilege and rollback drills.
- Before → action → after recovery evidence.
- PostgreSQL HA/DR and load/chaos acceptance.
- Internal registry signing/verification/promotion.
- Security review/red-team of MCP/tool abuse, prompt injection, identity, memory and supply chain.

## Verdict

The project now has a **single MCP external-tool boundary at the Control Plane** while preserving Evidence-first reasoning and Policy/Approval authority. This removes the previous architectural ambiguity between native and MCP paths. Strict Production Ready status still depends on real MCP server deployment, workload identity, external integration acceptance, HA/DR and scale/failure evidence.
