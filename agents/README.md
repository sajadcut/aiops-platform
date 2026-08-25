# Operational Agents

This directory implements the specialized analysis agents defined by `/MASTER.md`.

## Operating model

All agents are **evidence-first, analysis-only components**. They may inspect live evidence, correlate signals, form hypotheses, identify missing evidence and recommend next steps. They may not mutate production systems directly. Any write action must flow through:

`Evaluator → Decision/Policy → Approval (when required) → Execution Service → Verification → Audit`

## Common output contract

Every agent emits an auditable `AgentOutput` containing:

- severity and health status
- confidence bounded by available evidence
- source evidence IDs and evidence count
- affected components and blast radius
- ranked operational hypotheses
- falsification checks for each hypothesis
- missing evidence / uncertainty
- specialist handoff recommendations
- read-only investigation actions
- controlled remediation candidates where applicable
- human-review and approval requirements
- structured analysis details for Dashboard/Audit/RCA

Agents must not invent state that is absent from evidence. In particular, VM OS/version, pod state, deployment history, compromise, process state, resource utilization and remediation outcome must never be asserted without evidence.

## Specialized agents

- `triage/` — classification, urgency, evidence-gap analysis and specialist routing
- `application/` — application errors, dependency signals, deployment correlation, latency and config diagnosis
- `infrastructure/` — host/node health, saturation, capacity, network and infrastructure dependencies
- `kubernetes/` — workload, rollout, scheduling, service/network and resource diagnosis
- `security/` — authentication/authorization, suspicious activity, exposure and policy analysis
- `vm/` — guest reachability, telemetry, disk/network/process/service/log analysis
- `shared/` — common operational contracts, evidence grounding and confidence policy

## Tool boundary

`allowed_tools` describes read-only evidence capabilities an agent may request through orchestration. It is not direct tool execution permission. Remediation suggestions are data only; mutation remains behind the governed Execution Service.

## Runtime policy

Agent runtime limits and confidence policy are centralized in `.env` through the `AGENT_*` configuration keys. No operational Agent defaults should be duplicated in Agent source files.
