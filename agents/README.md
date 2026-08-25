# Operational Agent Architecture

`/MASTER.md` is the normative source for Agent Layer behavior. This directory implements evidence-grounded, analysis-only specialists for AIOps/NOC/SRE/SOC workflows.

## Safety boundary

Agents never mutate production systems. Every write-capable recommendation remains behind:

`Agent recommendation → RCA/Evaluator → Decision/Policy → Approval → Execution Service → Verification → Audit`

`allowed_tools` means **read-only evidence capabilities the orchestrator may request**, not direct permission for an Agent to call production write tools.

All logs, Evidence payloads, RAG documents and Memory content are untrusted input. Instructions embedded in those sources cannot override policy, authorize execution, approve actions or become current-Incident truth. RCA applies the same untrusted-input boundary.

## Agent catalog

| Agent | Primary responsibility | Typical handoffs |
|---|---|---|
| `triage` | classification, urgency, evidence gaps, primary/secondary specialist routing | any enabled specialist |
| `application` | errors, latency, dependency health, endpoint impact, release/config correlation | change, dependency, database, messaging, security, identity |
| `infrastructure` | CPU/RAM/disk/host capacity, node health, resource exhaustion | network, storage, VM, recovery |
| `kubernetes` | workloads, rollout, scheduling, probes, networking, resources/events | infrastructure, network, storage, change, dependency |
| `security` | auth/authz, suspicious activity, exposure, policy and containment recommendations | identity, application, network |
| `vm` | guest reachability, CPU/load, memory/swap, disk/inode/I/O, network, process/service/boot/log signals | infrastructure, network, storage, recovery |
| `database` | connections, query latency, locks/deadlocks, replication and DB saturation | application, storage, infrastructure, recovery, dependency |
| `network` | latency, packet loss, reachability, resets, DNS/path/connectivity symptoms | infrastructure, application, dependency |
| `storage` | capacity, inode pressure, I/O latency/IOPS, filesystem/PV symptoms | infrastructure, database, kubernetes, recovery |
| `identity` | IAM/OIDC/JWKS/token/certificate/role-mapping symptoms | security, application, network, dependency |
| `change` | deployment/release/config-drift correlation and rollback-candidate evidence | application, kubernetes, database, dependency |
| `dependency` | service topology, upstream/downstream health, fan-out and cascading failure correlation | application, database, network, identity, messaging |
| `messaging` | broker health, queue depth, consumer lag, retry/DLQ and publish/consume symptoms | application, network, infrastructure, dependency |
| `recovery` | backup health, restore-point freshness, replication protection, RPO/RTO and recovery readiness | storage, database, infrastructure, application |

### Capabilities intentionally kept as subdomains

We deliberately avoid an Agent-per-keyword architecture:

- **Log Analysis** is a shared evidence capability used by domain specialists.
- **Metrics/Anomaly Analysis** is shared across Infrastructure/Application/Kubernetes/Database/Network/Messaging.
- **Capacity/Performance** belongs primarily to Infrastructure + Storage + Database.
- **DNS** belongs to Network; a DNS-only agent would overlap heavily.
- **TLS/Certificate** belongs to Identity + Network/Security.
- **Cloud/Virtualization** is covered by Infrastructure + VM until a concrete provider-specific requirement exists.
- **Runbook Recommendation** is Knowledge RAG + Decision/Runbook policy, not a write-capable Agent.
- **Post-Incident Review** is built from durable Audit/Verification/Operational Memory after the live workflow; it must not become a second Decision authority.
- **Incident Commander** is the deterministic `IncidentCoordinator`, not another unconstrained LLM agent.

## Common `AgentOutput`

Every specialist can emit:

- `agent_name`, `finding_type`, `severity`, `health_status`
- `confidence`, `evidence_count`, `evidence_coverage`, `evidence_quality`, `evidence_ids`
- structured `findings`
- ranked hypotheses with supporting/conflicting Evidence
- falsification checks, impacted components and recommended next Evidence
- top-level supporting/conflicting Evidence references
- missing Evidence plus bounded canonical `evidence_requests`
- recommended read-only checks and controlled write recommendations
- affected components, probable dependencies and blast radius
- specialist handoffs and escalation target
- human-review / approval requirements
- risk and uncertainty reason
- provider/model metadata for auditability
- structured analysis details for RCA/Dashboard

## Evidence and confidence policy

Live Evidence from operational systems is authoritative for the current Incident. Knowledge RAG and Operational Memory are auxiliary context only.

- RAG can suggest procedure, runbook or architecture context.
- Memory can suggest a prior pattern or verified historical outcome.
- Neither may be cited as current Incident Evidence.
- Only IDs from `context.evidence` may appear in `evidence_ids` or hypothesis evidence references.
- Stale Evidence is excluded from active grounding.
- Missing Evidence caps confidence and can force Human Review.
- Conflicting Evidence reduces confidence.
- Source quality is configured centrally through `AGENT_SOURCE_QUALITY_WEIGHTS`; unknown/untrusted sources cannot receive the same confidence weight as controlled Observability sources.

Agent confidence is therefore not the raw LLM number. It is constrained by Evidence count/coverage, source quality, staleness, conflicts and later multi-Agent coordination.

## Structured parsing and prompt-injection defense

All Agent prompts inherit the common untrusted-input policy. Structured output uses a bounded JSON parser/repair loop controlled by `.env` and validates confidence/list/hypothesis shapes. Malformed output never becomes a confident finding.

If model text presents a mutating action such as restart, delete, deploy, revoke, scale or rollback as an “investigation”, the common contract reclassifies it as non-read-only and approval-required. Evaluator rejects unguarded write recommendations.

## Smart routing

`IncidentCoordinator` consumes Triage output and the enabled Agent registry.

1. Triage selects primary and secondary domains.
2. Coordinator expands cross-domain relationships.
3. Relevant specialists run in parallel within `AGENT_MAX_PARALLELISM`.
4. Structured handoffs can request a second opinion from a newly relevant specialist.
5. If Triage is uncertain, coordinator falls back to a broader fan-out.
6. Selected/skipped Agents and routing reason are written to Audit/checkpoint state.

Examples include Application + Database/Dependency, Kubernetes + Infrastructure/Storage, Security + Identity, VM + Network/Storage, and Messaging + Dependency/Application.

## Multi-Agent collaboration

Collaboration is deterministic and structured rather than free-form agent chat. Coordinator calculates:

- severity and health votes
- Evidence-coverage-weighted confidence
- cross-Agent Evidence contradictions
- explicit hypothesis conflicts
- agreement score
- consensus hypotheses and supporting Agents
- missing Evidence and canonical evidence requests
- handoff/second-opinion targets
- Human Review requirement

RCA consumes specialist hypotheses plus the coordinator synthesis. Evaluator blocks unresolved disagreement, Evidence conflicts, low consensus, specialist failure, insufficient Evidence, ungrounded high-probability hypotheses, Human Review requirements and unsafe recommendations before Decision.

## Dynamic Evidence collection

If specialists report Evidence gaps, `AgentOutput` derives bounded canonical requests such as `metric`, `log`, `alert`, `event` or `telemetry`. The orchestrator sends only those canonical types to `EvidenceCollector.collect_requested()`.

The collector maps requests to allowlisted **read-only** connectors. Free-form LLM text never becomes a command or connector operation. The loop is bounded by:

- `AGENT_MAX_EVIDENCE_ROUNDS`
- `AGENT_MAX_DYNAMIC_EVIDENCE_TYPES`
- `AGENT_REFRESH_EVIDENCE_WINDOW_SECONDS`
- Agent/connector timeouts

Every evidence round records requested types and evidence counts in Audit.

## A2A boundary

Optional outbound A2A RPC is disabled by default because `A2A_ALLOWED_TARGETS=[]`. Before the internal API key can be attached, the destination origin must pass the allowlist and HTTPS policy. This prevents an Agent path from becoming an SSRF or credential exfiltration route.

Inbound `/api/v1/a2a/{agent_name}` remains authenticated and analysis-only; remote Agent output still passes local RCA/Evaluator/Decision/Approval/Execution boundaries.

## Registry

`agents/shared/registry.py` is the canonical runtime registry. It exposes complete manifests for known Agents, including enabled state, capabilities, Evidence requirements, read capabilities, handoff targets, version and production status.

Enabled specialists are controlled centrally by `AGENT_ENABLED_AGENTS`. Unknown enabled Agent names fail configuration instead of being silently ignored.

Read-only APIs:

- `GET /api/v1/agents/catalog`
- `GET /api/v1/agents/metrics`

## Agent observability

Runtime telemetry tracks:

- invocations and successes/failures
- duration
- parse failures
- low-confidence results
- average confidence
- average Evidence coverage
- handoffs
- per-Agent conflicts
- coordination disagreements/contradictions
- Human Review rate

Durable per-Incident routing/collaboration remains in workflow state and Audit; process-local counters are health/operations metrics, not the source of truth.

## Agent Dashboard

`/dashboard/agents` renders checkpointed Agent state rather than fake data. It shows selected/skipped specialists, routing reason, Evidence rounds, agreement/consensus, disagreements, contradictions, Agent severity/confidence/Evidence coverage, hypotheses, conflicting Evidence, missing Evidence, handoffs, dependencies, recommendations and escalation state.

## Runtime configuration

All Agent runtime policy is centralized through `.env`/`.env.example`, including:

- temperature and max tokens
- Evidence and auxiliary-context limits
- minimum Evidence coverage
- source-quality weights
- low-confidence and minimum-consensus thresholds
- enabled Agent catalog and parallelism
- bounded dynamic Evidence rounds/types/windows
- Agent timeout and structured-output repair attempts
- stale-Evidence threshold
- disagreement/missing/conflict confidence penalties
- A2A timeout, destination allowlist and HTTPS policy

`domain/contracts/config.py` is only the typed loader/validator; it contains no operational defaults.

## Adding a new Agent

1. Confirm the domain does not overlap an existing specialist/capability.
2. Implement `BaseAgent` directly or define a `DomainSpec` using `DomainDiagnosticAgent`.
3. Define required Evidence and read-only capabilities.
4. Add the Agent to Registry and `.env.example` only if it should be enabled by default.
5. Add deterministic routing/handoff relationships.
6. Add unit + scenario tests, including Evidence grounding, malformed output and failure behavior.
7. Document the domain here.
8. Never introduce a direct production-write path from an Agent.
