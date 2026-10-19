# Cognia service relevance: mandatory incident admission control

For any incident, Cognia search ranking is **not** evidence of ownership. The
AIOps boundary rejects documents with a different explicit service, and
quarantines unscoped chunks (including plausible how-to prose) unless the author
declares `Applicability: general` or the matching `metadata.applicability`
value `general` / `cross-service` / `all-services`. Cognia authorization
scope `general` means visibility, NOT service applicability.

A document with `Service: nginx` is not usable in an incident whose verified
service is `gfpapi` even if Cognia ranks it first. Use `Service: gfpapi` (or
structured metadata `service: gfpapi`) for service-specific chunks. An
incident with no known service only accepts an explicitly generic document or
topology referring to an **exact source-notification FQDN**. A matching FQDN is
a read-only discovery hint and requires live MCP verification before writes.

All incident paths use the same policy: SignalGateway, ContextBuilder, E2E
Orchestrator, SignalAware merging, Dynamic Investigation, incident copilot,
Agent prompt construction, incident knowledge API, and Decision Brief.
Every retrieval/filter path records accepted/rejected counts and bounded source
references. Filtering never changes active Cognia revisions or deletes
historical incident evidence. Previously created incident knowledge snapshots
should be reviewed separately; do not rewrite Audit/Approval data.

## Early service orientation for every incoming alert

Before correlation and specialist routing, `SignalGateway` queries Cognia for
topology (all alerts) and, when an explicit service identity is available,
separately searches for that service's architecture, runtime, framework,
configuration file locations, upstream dependencies and troubleshooting context.
The two result sets are interleaved, deduplicated by source reference, and
admitted through the same relevance gate. An unknown-service alert does not
inherit arbitrary service-owned runbooks. A partial Cognia failure remains
visible as `partial` and does not prevent normal live-evidence collection.

The E2E context phase rechecks relevance and retains service-scoped ingress
knowledge when possible instead of replacing it with a new search result.
**Incident subject scopes are stronger than ingress searches**: unscoped
ingress documents cannot be reused under a tenant/subject-specific scope.

Explicitly service-owned documents may supply **advisory-only** structural
hints such as `Runtime: dotnet`, `Dependency: SQLServer`, or
`Config File: /data/gfpapi/appsettings.json`. Only bounded allowlisted
hint shapes and source references are projected into the triage LLM prompt.
The `early_service_orientation` field in the Decision Brief and incident
investigation ledger shows these hints with `verified=false`. Their paths,
runtime claims and endpoints can **never** become SSH targets, command
arguments or verified config files; independent MCP observation is required.

The LLM combines this auxiliary context with live Zabbix/Elastic/Prometheus,
VM MCP, and other available evidence to route specialists and request registered
read-only checks. Cognia is not a required-availability dependency for incident
ingestion, and a successful knowledge hit is not a root-cause, health or
configuration validation result.

## Migration of existing knowledge

Curate Cognia documents to include an explicit owner service or validated
cross-service applicability. Missing metadata is quarantined, not guessed by
an LLM. Keep a separate human-reviewed multi-service topology/dependency map;
a textual mention of a proxy, DB or queue never authorizes a dependency claim.

## Validation

Run `python -m pytest -q tests/unit/test_cognia_service_relevance_gate.py
tests/unit/test_service_identity_resolution.py
tests/unit/test_signal_service_identity_guard.py
tests/unit/test_knowledge_topology_resolution.py`, then the repository's
full CI. Real Cognia Search, metadata delivery and Windows/VM/Zabbix
integration still require staging acceptance before production PASS.
