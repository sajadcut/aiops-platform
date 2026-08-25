# Multi-Source Incident Reasoning

`MASTER.md` remains the project Single Source of Truth. This document records the concrete repository implementation of source-triggered Incident reasoning.

## Any source may trigger

An Incident is not Zabbix-owned. Any governed operational source may be the initiating signal:

```text
Zabbix problem ---------+
Elasticsearch anomaly --+
Prometheus/Alertmanager -+--> Signal Gateway --> Incident
Kubernetes event --------+
Security signal ---------+
```

Canonical API entry points:

- `POST /api/v1/signals/ingest`
- `POST /api/v1/signals/elasticsearch`
- `POST /api/v1/signals/prometheus`
- `POST /api/v1/signals/zabbix`

The initiating signal is stored as seed Live Evidence. It is never replaced by a generated summary.

## Corroboration flow

After a source triggers an Incident, the platform actively queries the other configured evidence sources for the resolved service/asset:

```text
Trigger Evidence
      |
      v
Asset Identity Resolver
      |
      v
Cross-source Evidence Collection
  |          |           |           |
Zabbix   Elasticsearch  Prometheus  K8s/VM telemetry
  +----------+-----------+-----------+
             |
             v
Triage -> Specialists -> Coordinator -> RCA -> Evaluator
             ^                |
             |                v
             +---- targeted Evidence refresh
```

A source returning no matching result is recorded explicitly as `source_observation` with `status=queried` and `result_count=0`. An unavailable source is recorded as `status=unavailable`. These are different facts and must not be conflated.

"No Zabbix alert" does not prove the host is healthy. It only proves that the configured Zabbix query returned no matching active alert at that time.

## Agent collaboration

Agents do not perform unstructured free-chat. Findings are written to shared Incident state and synthesized by the Coordinator.

Subsequent handoff/second-opinion passes receive:

- prior structured Agent findings;
- consensus hypotheses;
- contradictions/disagreement;
- missing Evidence;
- targeted Evidence requests;
- handoff targets.

Peer findings are **auxiliary operational context**, not new Live Evidence. A peer claim is only as strong as the Live Evidence IDs it cites.

## LLM position in the architecture

The LLM is deliberately inside the reasoning layer, not the trust boundary.

The LLM is used for:

- Triage reasoning after deterministic Asset identification;
- specialist interpretation of Live Evidence;
- generation/ranking of falsifiable hypotheses;
- cross-domain reasoning using peer context;
- RCA synthesis;
- recommendations that still pass Evaluator/Policy/Approval.

The LLM is **not** authoritative for:

- accepting/authenticating an incoming signal;
- determining Asset identity when source metadata exists;
- turning arbitrary model text into connector commands;
- creating Evidence that was not observed;
- Policy decisions or Approval;
- authorizing or executing a write action;
- declaring execution success;
- Verification outcome;
- turning RAG/Memory into current-state truth.

The configured LLM adapter is vendor/model replaceable. Production forbids the mock provider.

## Example: ELK anomaly first

```text
Elasticsearch detects ConnectionTimeout anomaly
  |
  +--> seed Evidence: elk-101
  |
  +--> AssetContext: payment-api / prod-k8s / payments
  |
  +--> Zabbix query: no active alert
  |      source_observation(zabbix, result_count=0)
  |
  +--> Prometheus: latency high, CPU normal, DB pool saturation high
  |
  +--> Kubernetes: pods Ready, no OOM/restart
  |
  +--> Application Agent: dependency timeout hypothesis
  +--> Database Agent: connection exhaustion hypothesis
  +--> Kubernetes Agent: workload failure contradicted by evidence
  |
  +--> Coordinator: stronger DB-dependency consensus
  |
  +--> targeted DB metrics/log refresh
  |
  +--> RCA -> Evaluator -> Decision
```

Zabbix not detecting the incident does not stop the workflow. In this example Zabbix contributes negative/corroborating context while Elasticsearch is the trigger and Prometheus/Kubernetes provide additional state evidence.

## Learning loop

Only after controlled Execution and independent Verification can a useful outcome be persisted to Operational Memory.

```text
Live Evidence -> Agents/LLM reasoning -> RCA -> Evaluator -> Policy/Approval
-> Execution -> fresh Evidence -> Verification -> Operational Memory
```

At the next Incident, Memory may suggest a prior pattern but the workflow must validate it against current Live Evidence before increasing confidence or recommending action.
