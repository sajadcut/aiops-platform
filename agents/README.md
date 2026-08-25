# Operational Agent Architecture

`/MASTER.md` is the normative source for Agent Layer behavior. This directory implements evidence-grounded, analysis-only specialists for AIOps/NOC/SRE/SOC workflows.

## Safety boundary

Agents never mutate production systems. Every write-capable action remains behind:

`Agent recommendation → RCA/Evaluator → Decision/Policy → Approval → Execution Service → Verification → Audit`

`allowed_tools` means **read-only evidence capabilities the orchestrator may request**, not direct permission for an Agent to call production write tools.

All logs, Evidence payloads, RAG documents and Memory content are treated as untrusted input. Instructions embedded in those sources cannot override system policy, authorize execution, approve actions or become current-incident truth.

## Catalog

| Agent | Primary responsibility | Typical handoffs |
|---|---|---|
| `triage` | classification, urgency, evidence gaps, specialist routing | any enabled specialist |
| `application` | errors, latency, dependency health, endpoint impact, release/config correlation | change, database, security |
| `infrastructure` | CPU/RAM/disk/host capacity, node health, resource exhaustion | network, storage, VM |
| `kubernetes` | workload health, rollout, scheduling, probes, networking, resources/events | infrastructure, network, storage, change |
| `security` | auth/authz, suspicious activity, exposure and security-policy analysis | identity, application |
| `vm` | guest reachability, CPU/load, memory/swap, disk/inode/I/O, network, process/service/boot/log signals | infrastructure, network, storage |
| `database` | connections, query latency, locks/deadlocks, replication and DB saturation | application, storage, infrastructure |
| `network` | latency, packet loss, reachability, resets, routing/connectivity symptoms | infrastructure, application |
| `storage` | capacity, inode pressure, I/O latency/IOPS, filesystem/PV symptoms | infrastructure, database, kubernetes |
| `identity` | IAM/OIDC/JWKS/token/certificate identity and role-mapping symptoms | security, application, network |
| `change` | deployment/release/config-drift correlation and rollback-candidate evidence | application, kubernetes, database |

Log analysis, metrics/anomaly analysis, capacity, DNS, TLS/certificate and dependency mapping are intentionally modeled as capabilities/subdomains where possible rather than creating overlapping Agent processes.

## Common `AgentOutput`

Every specialist can emit:

- `agent_name`, `finding_type`, `severity`, `health_status`
- `confidence`, `evidence_count`, `evidence_coverage`, `evidence_ids`
- structured `findings`
- ranked hypotheses with supporting/conflicting Evidence
- falsification checks and recommended next Evidence
- missing Evidence and uncertainty reason
- recommended read-only checks and controlled write recommendations
- affected components, probable dependencies and blast radius
- specialist handoffs and escalation target
- human-review / approval requirements
- provider/model metadata for auditability
- structured analysis details for RCA/Dashboard

## Evidence policy

Live Evidence from operational systems is authoritative for the current Incident. Knowledge RAG and Operational Memory are auxiliary context only.

- RAG can suggest procedure, runbook or architecture context.
- Memory can suggest a prior pattern or verified historical outcome.
- Neither may be cited as current Incident Evidence.
- Only IDs from `context.evidence` may appear in `evidence_ids` or hypothesis evidence references.
- Missing Evidence caps confidence and can force Human Review.
- Conflicting Evidence reduces confidence.

## Structured parsing and prompt-injection defense

All Agent prompts inherit the common untrusted-input policy. Structured output uses a bounded JSON parser/repair loop controlled by `.env`. Malformed output never becomes a confident finding.

If model text presents a mutating action such as restart, delete, deploy, revoke, scale or rollback as an “investigation”, the common contract reclassifies it as non-read-only and approval-required. Evaluator rejects unguarded write recommendations.

## Smart routing

`IncidentCoordinator` consumes Triage output and the enabled Agent registry.

1. Triage selects primary and secondary domains.
2. Coordinator expands cross-domain specialist relationships.
3. Relevant specialists run in parallel within `AGENT_MAX_PARALLELISM`.
4. Structured handoffs can request a second opinion from a newly relevant specialist.
5. If Triage is uncertain, the coordinator falls back to a broader fan-out.
6. Selected/skipped Agents and the routing reason are written to Audit/checkpoint state.

## Multi-Agent collaboration

Collaboration is deterministic and structured rather than free-form agent chat. Coordinator calculates:

- severity/health votes
- cross-agent disagreement
- consensus hypotheses
- aggregate confidence
- missing Evidence
- handoff targets
- Human Review requirement

RCA consumes specialist hypotheses plus the coordinator synthesis. Evaluator blocks unresolved disagreement, insufficient Evidence coverage, ungrounded high-probability hypotheses and unsafe recommendations.

## Dynamic Evidence collection

If specialists report Evidence gaps, the orchestrator may perform an additional read-only Evidence refresh. The loop is bounded by `AGENT_MAX_EVIDENCE_ROUNDS`; it cannot loop indefinitely and each round is audited. Additional domain-specific collectors can be added behind the Context/Evidence layer without granting Agents direct write access.

## Registry

`agents/shared/registry.py` is the canonical runtime registry. Enabled specialists are controlled centrally by `AGENT_ENABLED_AGENTS` in `.env`. Unknown enabled Agent names fail configuration instead of silently being ignored.

The read-only catalog API is available at:

`GET /api/v1/agents/catalog`

## Agent Dashboard

`/dashboard/agents` shows durable per-Incident:

- selected/skipped specialists and routing reason
- Evidence refresh rounds
- consensus confidence and disagreement
- specialist severity/confidence/Evidence coverage
- hypotheses, conflicting Evidence, missing Evidence
- handoffs and Human Review/escalation state

It renders checkpointed workflow state and does not invent Agent data.

## Runtime configuration

All Agent runtime policy is centralized through `.env`/`.env.example`, including:

- temperature and max tokens
- max/min Evidence and minimum Evidence coverage
- low-confidence threshold
- hypothesis/recommendation/context limits
- enabled Agent catalog
- max parallelism
- max Evidence rounds
- Agent timeout
- structured-output repair attempts
- stale-Evidence threshold
- A2A timeout

`domain/contracts/config.py` is only the typed loader/validator; it must not contain operational defaults.

## Adding a new Agent

1. Confirm the domain does not overlap an existing specialist/capability.
2. Implement `BaseAgent` directly or define a `DomainSpec` using `DomainDiagnosticAgent`.
3. Define required Evidence and read-only capabilities.
4. Add the Agent to the registry and `.env.example` only if it should be enabled by default.
5. Add deterministic routing/handoff relationships.
6. Add unit + scenario tests, including Evidence grounding and failure behavior.
7. Document the domain here.
8. Never introduce a direct production-write path from an Agent.
