# Incident Room Copilot — Incident-scoped investigative chat

This capability appears as **Incident Chat** beside **Received Alert** in the
Incident Command Room, after the incident analysis is saved. The chat is NOT a
generic free-form shell or an alternative execution permission model.

## Workflow

1. The operator opens a specific Incident and asks a question. History is
   stored durably in redacted incident-scoped PostgreSQL Audit events and is
   shared with authorized incident readers. The UI reloads history on revisit.
2. The copilot receives bounded decision-brief facts, Agent findings and
   knowledge context, and recent incident conversation. It can request a
   typed, allowlisted VM MCP read (service status, bounded logs, config check,
   nginx structural review, .NET runtime/JSON syntax) or scoped Cognia search.
   Read checks require no mutation confirmation.
3. The VM target and service are **never** taken from the LLM. They must agree
   with a uniquely corroborated VM MCP service_status record within this
   Incident; conflicting live targets or original-alert identity prevent
   binding. A user cannot redirect a chat read or action to a different host.
4. A model-generated or explicitly requested Start, Restart or Reload
   becomes an advisory card, **not execution**. Clicking Request approval
   requires high-risk RBAC and triggers fresh live service/configuration
   preconditions. If they pass, the existing Remediation API creates a separate
   hash/digest-bound, persistent pending Approval on **this** Incident.
5. In the same chat card, a privileged operator can then separately Approve
   and Execute. Execution consumes the one-time Approval through the existing
   guarded remediation executor; post-execution verification is unchanged.
   Chat text and returned LLM JSON cannot approve, execute, select commands,
   override the target or invent a PASS.

## .NET service recovery preflight (approved Start/Restart only)

When generic `config_validate` reports `config_validation_adapter_unavailable`,
the runtime guard re-checks the exact bound VM/service via
`service_runtime_discovery`. Only an independently discovered .NET DLL
runtime triggers `dotnet_config_syntax`, which parses bounded files locally
on the **AIOps** server (remote Python is not installed). For **start/restart
only**, a successful, supported, complete `json_syntax_only` validator can
satisfy the limited preflight if its provenance, runtime binding and every
file status agree. This is **not** proof that application settings or
dependencies are valid or that the service will start. It never enables
automatic remediation planning, reload, auto-approval or direct execution.

Any unavailable/partial/invalid JSON check, missing runtime identity,
mismatched target/service, or contradictory evidence blocks preflight.
Approved operations still re-read live VM evidence immediately before
execution, consume the normal Approval and undergo post-execution verification.
The approval Audit records `preflight_validation_scope=dotnet_json_syntax_only`
and `configuration_semantics_valid=null`. The operator must explicitly
review the runtime/startup timeout and application dependency risks.

## Reload-specific policy

The VM recovery runbook now lists Reload as a high-risk, governed action.
Unlike Start/Restart, **Reload requires a currently active service** and a
fresh, supported, successful `config_validate` result. A failed, inactive,
unknown, inconsistent or syntactically invalid service is NOT eligible for
Reload; the operator is shown a blocked live-preflight result. This is crucial
for a stopped Nginx with a syntax failure: Reload must not be proposed as
an executable workaround for a known invalid configuration.

A queued approval still cannot execute if the service or config changes before
execution. The normal runtime guard rechecks fresh MCP observations.

## Persistence, UI, permissions and limitations

- A new tab and form, bilingual FA/EN, with keyboard submission, live
  progress/error messaging, evidence refs and action cards.
- No cross-incident chat session reference, arbitrary SSH, patch Apply or
  LLM-selected VM target. All reads are restricted to the registered VM MCP.
- `GET /api/v1/incidents/{id}/chat`: incident read permission.
- `POST /api/v1/incidents/{id}/chat`: incident read + strict rate limiting.
- `POST /api/v1/incidents/{id}/chat/request-approval`: high-risk approval
  permission + live preflight + strict rate limiting; it does **not** execute.
- POST /api/v1/approvals/{id}/approve and
  POST /api/v1/approvals/{id}/execute remain independent protected operations.
- Agent findings are referenced from the stored report; this iteration does
  not restart the whole multi-agent LangGraph during every chat message.
  Cognia follow-up is scoped to the existing incident knowledge subject.
- For incidents with no unique corroborated VM identity, explanation/knowledge
  chat works but VM commands are blocked. Kubernetes-oriented investigation
  should use the general governed Chatbot until a per-incident K8s binding
  resolver is implemented.
- Safety/production acceptance on real VM and Cognia, OIDC permission roles,
  workflow race tests and staging rollback remain **REAL ENV REQUIRED**.
- No auto-approval, autonomous mutation, unsafe shell, or config write.
