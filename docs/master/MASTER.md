# AI Ops Platform
## Master Project Specification & Current Implementation Status

---

## 1. Project Overview

AI Ops Platform is an AI-driven operational intelligence and incident-response platform designed to:

- Receive operational incidents
- Collect and normalize operational context
- Retrieve relevant knowledge using RAG
- Retrieve similar historical incidents
- Analyze incidents using specialized agents
- Determine probable root cause
- Generate an operational decision
- Apply human approval when required
- Execute operational actions through controlled tools
- Verify execution results
- Store operational outcomes as organizational memory
- Continuously improve future incident handling

The platform is being implemented incrementally.

---

# 2. Current Development Strategy

The development environment currently does NOT have:

- Elasticsearch
- Zabbix
- Prometheus
- Kubernetes production access

Therefore the development phase uses:

- Mock operational context
- PostgreSQL
- pgvector
- Mock execution tools
- Simulated before/after metrics

The architecture is intentionally being developed so that real infrastructure adapters can replace the mock implementations later.

---

# 3. High-Level Architecture

```text
                         ┌─────────────────────┐
                         │      Incident       │
                         │       Source        │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Incident API     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │  Context Builder    │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
          ┌──────────────────┐             ┌──────────────────┐
          │       RAG        │             │ Similar Incidents│
          │ Knowledge Search │             │ OperationalMemory│
          └────────┬─────────┘             └────────┬─────────┘
                   │                                │
                   └───────────────┬────────────────┘
                                   ▼
                         ┌─────────────────────┐
                         │   LangGraph /       │
                         │   Orchestrator      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Triage Agent     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                    ┌───────────────┴───────────────┐
                    │       Parallel Analysis       │
                    ├──────────────┬────────────────┤
                    ▼              ▼                ▼
               Application   Infrastructure   Kubernetes
                    │              │                │
                    ├──────────────┼────────────────┤
                    ▼              ▼                ▼
                Security           VM        Other Agents
                    │
                    └──────────────┬────────────────┘
                                   ▼
                         ┌─────────────────────┐
                         │      RCA Engine     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Decision Engine   │
                         └──────────┬──────────┘
                                    │
                       ┌────────────┴────────────┐
                       ▼                         ▼
                Auto Execute              Human Approval
                       │                         │
                       │                    Approval API
                       │                         │
                       └────────────┬────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │    Action Planner   │
                         │   / ActionPlan      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │  Execution Service  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Tool Registry    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Tool / Executor   │
                         │   Mock for Dev      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Verification Engine │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Operational Memory  │
                         └─────────────────────┘