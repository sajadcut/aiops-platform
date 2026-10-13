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
