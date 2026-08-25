# AIOps / Agentic AI Benchmark 2026

Assessment date: 2026-08-26

This document records the benchmark-driven architecture review against current public guidance and mature operational systems. `MASTER.md` remains the SSoT for project architecture; this benchmark cannot silently override it.

## External references used

The review used these reference families for design principles, not blind feature copying:

1. NIST AI Agent Standards Initiative — secure/interoperable agents, identity and authorization.
2. OWASP Top 10 for Agentic Applications 2026 — goal hijacking, tool misuse, identity abuse, memory poisoning, insecure inter-agent communications, cascading failures and rogue agents.
3. Model Context Protocol authorization specification (2025-11-25) — OAuth 2.1, Protected Resource Metadata, RFC 8707 resource binding and no token passthrough.
4. LangGraph persistence / interrupts / human-in-the-loop — durable checkpoints, resumable state and idempotent side effects around interrupts.
5. Temporal — crash-proof durable workflow reference architecture.
6. OpenTelemetry GenAI semantic conventions — model/tool spans, latency and token usage with sensitive-content controls.
7. Prometheus Alertmanager — grouping, deduplication, inhibition and explicit HA semantics.
8. Open Policy Agent — policy/data separation, decision logs, signed bundles and distributed enforcement.
9. SPIFFE/SPIRE — short-lived workload identity, SVIDs and mTLS.
10. Sigstore/Cosign — artifact signature, identity/digest verification and attestations.
11. HolmesGPT — cross-tool SRE investigation and RCA reference.
12. Robusta — Kubernetes alert enrichment/remediation patterns.
13. StackStorm — deterministic sensor/trigger/rule/action/workflow automation, action audit and concurrency policies.
14. Rundeck/Process Automation — governed runbooks, ACLs, remote runners and clustered automation patterns.
15. KEDA — event-driven worker scaling reference.
16. Patroni — PostgreSQL HA and split-brain safety.
17. pgBackRest — backup/WAL/PITR reference.
18. LitmusChaos — failure/chaos validation, including restricted/air-gapped environments.
19. Keptn — historical SLO/quality-gate/remediation pattern only; not selected as an active dependency.
20. CNCF/OpenTelemetry ecosystem patterns for platform observability and cloud-native operations.

## 60-control benchmark matrix

Scoring is repository/code-contract maturity, not external production acceptance.

| # | Control | Score | Evidence / benchmark conclusion |
|---:|---|---|---|
| 1 | Signal ingestion | Strong | Source-agnostic Zabbix/Elastic/Prometheus/K8s/manual gateway. |
| 2 | Cross-source correlation | Adequate | Deterministic fingerprint + bounded window + PG lock added; real corpus acceptance remains. |
| 3 | Incident deduplication | Adequate | Exact event idempotency + race lock + cross-source merge for eligible families. |
| 4 | Asset/service identity | Strong | Deterministic multi-source AssetIdentityResolver. |
| 5 | CMDB/service catalog | Weak | RAG source type exists; no authoritative live CMDB adapter/identity precedence. |
| 6 | Evidence normalization | Strong | Canonical evidence/source observation contracts. |
| 7 | Evidence provenance | Adequate | source/reference/timestamp/raw data retained; cryptographic provenance absent. |
| 8 | Negative evidence handling | Strong | queried-zero separated from unavailable/error/skipped. |
| 9 | Agent routing | Strong | deterministic asset routing + Triage specialist selection. |
| 10 | Multi-agent collaboration | Strong | peer context, coordinator, bounded handoff/evidence refresh. |
| 11 | Agent-to-agent protocol | Partial | structured internal state; optional A2A is not a mature standardized identity-bound fabric. |
| 12 | Agent identity | Weak | logical agent registry exists; cryptographic runtime identity absent. |
| 13 | LLM authority boundaries | Strong | LLM cannot authorize/execute writes. |
| 14 | Prompt injection protection | Strong | evidence/RAG/memory treated as untrusted; execution separated. |
| 15 | Tool discovery | Adequate | governed Tool Registry; dynamic third-party discovery intentionally limited. |
| 16 | MCP client/server | Weak | legacy clients deprecated; modern governed MCP adapter not implemented. |
| 17 | Tool capability governance | Strong | allowlists, typed requests, risk/approval binding. |
| 18 | Least privilege | Adequate | read-only collectors and constrained SSH; external account/RBAC acceptance remains. |
| 19 | Policy engine | Adequate | deterministic internal engine; lacks OPA-grade versioned/signed distributed policy management. |
| 20 | Approval workflow | Strong | durable binding + one-time consumed state. |
| 21 | Execution isolation | Adequate | service boundary strong; runtime sandbox/edge isolation incomplete. |
| 22 | Linux remediation | Adequate | allowlisted SSH actions; real target acceptance pending. |
| 23 | Windows remediation | Missing | no mature constrained native WinRM/JEA/Edge implementation. |
| 24 | Kubernetes remediation | Partial | evidence strong; write/runbook adapter breadth incomplete. |
| 25 | Database remediation | Weak | specialist analysis exists; governed DB action adapter incomplete. |
| 26 | Network remediation | Weak | specialist analysis exists; governed network action adapter incomplete. |
| 27 | Rollback | Partial | runbook contract supports rollback; real adapter/rollback drills incomplete. |
| 28 | Idempotency | Adequate | approval consumption, evidence/finding dedupe, signal event/correlation locks. |
| 29 | Verification | Adequate | fresh baseline + metric semantics + independent stage. |
| 30 | Per-action success criteria | Partial | generic verification exists; explicit SLO objective per runbook incomplete. |
| 31 | RCA quality | Adequate | evidence-linked synthesis + conflicts; real labeled corpus accuracy pending. |
| 32 | Evaluator/critic | Strong | mandatory gate before Decision. |
| 33 | RAG governance | Strong | source allowlist/owner/version/ACL + pgvector. |
| 34 | Operational Memory | Adequate | separate namespace and verified-outcome writeback; scale/false reuse pending. |
| 35 | Memory poisoning protection | Adequate | memory auxiliary and revalidated against live evidence; provenance/signing can improve. |
| 36 | Audit | Strong | PostgreSQL audit and workflow events. |
| 37 | OIDC/RBAC | Adequate | signed JWT validation and permissions; enterprise acceptance pending. |
| 38 | Workload identity/mTLS | Weak | HTTPS/allowlist exists; SPIFFE-like short-lived identity not implemented. |
| 39 | Secrets management | Partial | centralized env/K8s Secret contract; dedicated secret broker/rotation not proven. |
| 40 | API security | Adequate | auth/RBAC/rate limits/error hygiene; external pen test pending. |
| 41 | Distributed rate limiting | Weak | current limiter process-local. |
| 42 | Queues/workers | Missing | message-broker/work queue remains an explicit Open Decision. |
| 43 | Retries/backpressure | Partial | bounded retries/timeouts exist; global admission/backpressure missing. |
| 44 | Durable workflow | Adequate | PostgreSQL app checkpoint/resume; not native step-level distributed durability. |
| 45 | HA | Partial | pod hardening/PDB/topology exist; end-to-end HA unproven. |
| 46 | PostgreSQL HA | Missing | no accepted Patroni/operator topology. |
| 47 | Backup/restore/DR | Missing | no tested pgBackRest/PITR/DR exercise. |
| 48 | AI platform observability | Partial | logs/health/audit exist; end-to-end OTel not implemented. |
| 49 | Agent metrics/tracing | Partial | process-local AgentTelemetry; no distributed OTel spans. |
| 50 | LLM metrics/cost/latency | Weak | adapter timeouts exist; standardized token/latency/cost telemetry incomplete. |
| 51 | Offline deployment | Adequate | non-root fail-closed offline image/K8s contracts; real mirror acceptance pending. |
| 52 | Software supply chain | Adequate | hygiene/signing workflow contracts; external promotion verification remains. |
| 53 | Signed immutable artifacts | Partial | definitions/workflow exist; internal registry acceptance pending. |
| 54 | CI/CD | Strong | full suite + DB migration/pgvector acceptance. |
| 55 | Testing strategy | Strong | unit/integration/scenario/security/failure contracts. |
| 56 | Scenario tests | Strong | reference scenarios and multi-source tests exist. |
| 57 | Chaos/failure testing | Weak | failure injection exists; full chaos environment not accepted. |
| 58 | Load/soak testing | Missing | no 500-incident sustained admission/throughput evidence. |
| 59 | Red-team/adversarial | Partial | prompt/tool safety tests exist; formal agentic red-team program incomplete. |
| 60 | Production acceptance | Partial | repo strong; real endpoint/execution/HA/DR/identity/load evidence incomplete. |

## Target architecture decision

The target is **hybrid hierarchical AIOps**:

```text
Central AIOps Control Plane
  Signal Gateway / Context / Asset Identity
  LangGraph + LLM + Triage + Specialist Agents
  Coordinator / RCA / Evaluator
  Decision / Policy / Approval
  Execution Controller
  PostgreSQL + pgvector / Audit / Memory
        |
        | authenticated + audited capability channel
        v
Optional constrained Edge Runtime
  Linux VM       Windows VM       Kubernetes Node DaemonSet
  read telemetry read telemetry   node-local evidence
  allowlisted    allowlisted      allowlisted actions
```

Reasoning authority remains central. Edge runtime is Eyes/Hands, not an autonomous LLM brain. No per-Pod AI Agent is required.

## MCP decision

MCP is **selected transport, not universal transport**. Keep native governed connectors for fixed internal Observability APIs. Use a future modern MCP adapter where capability discovery/interoperability materially helps (third-party tools or constrained Edge runtime). Remote privileged MCP must implement current auth semantics and must still pass through Tool Registry → Policy → Approval → Audit. The legacy JSON-RPC clients are explicitly non-production.

## Patterns deliberately not copied

- Do not copy broad arbitrary shell/bash remediation from generic automation systems into the Agent path.
- Do not give the SRE Agent cluster-admin simply because another Kubernetes troubleshooting product can use broad permissions.
- Do not replace PostgreSQL/pgvector with a separate vector DB without scale evidence/ADR.
- Do not make Temporal/Redis/RabbitMQ/Kafka a hidden dependency while Message Broker remains an Open Decision.
- Do not use a public SaaS-only identity/LLM/signing assumption in Offline Production.
- Do not adopt archived Keptn as a platform dependency; only reuse its SLO/quality-gate idea.

## Highest-value remaining benchmark gaps

1. CMDB/service catalog authoritative identity.
2. Correlation accuracy corpus + late-signal re-analysis semantics.
3. Windows constrained Edge/WinRM/JEA implementation.
4. Per-runbook verification/SLO objectives.
5. Governed Kubernetes/Ansible/Jenkins/DB/network write adapters.
6. Distributed queue/workers/admission/backpressure.
7. Distributed rate limiting.
8. PostgreSQL HA and pgBackRest-style PITR/DR acceptance.
9. Short-lived workload identity/mTLS.
10. OpenTelemetry GenAI/agent/tool tracing.
11. Modern MCP adapter for selected integrations only.
12. Formal chaos/load/red-team acceptance.
