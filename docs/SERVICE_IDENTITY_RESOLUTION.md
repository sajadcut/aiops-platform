# Service Identity Resolution — verifiable service labels (v1)

The same deterministic resolution policy is now used by **SignalGateway**,
**ContextBuilder**, and **SignalAwareE2EOrchestrator**:
`apps/context_service/service_identity.py`.

## Why

Generic Zabbix CPU / memory / filesystem alerts must **not** become "nginx"
because an unrelated Cognia document discussed nginx, because a VM happens to
have an nginx process, or because an LLM guessed it. The monitoring host is
separately retained and displayed as `هشدار سرور: <hostname>` where known.

## Authority and provenance

| Status | Meaning | Execution authority |
|---|---|---|
| `reported` | Source-supplied `service` or trusted vendor tag/label | No |
| `verified` | Source declaration corroborated by a successful live MCP `service_status` on the **same explicit target** | No |
| `observed` | Live read-only monitoring observed a service but its relationship to the alert is unconfirmed | No |
| `suspected` | Exact alert FQDN matches a service/FQDN pair in Cognia | No |
| `unknown` | No defensible service identity | No |

`suspected_service` is always advisory, including `cognia` and `llm_hypothesis` provenance. No fabricated confidence is assigned.

- Explicit source service wins over unrelated Cognia documents. Conflicting
  source vs MCP identities are recorded, never silently overwritten.
- Matching **source-notification FQDN** with the explicit FQDN in the retrieved
  topology can scope read-only diagnostics. It still requires independent live
  confirmation before a write.
- Plain source Host/hostname is not treated as a service or sufficient knowledge
  linkage. Generic operating-system alerts with no service stay `unknown`.
- MCP `source_observation` failures, arbitrary process listings and unscoped
  knowledge content are not independent service verification.
- Where a real LLM is configured, unresolved identity may receive a read-only
  bounded-time suggestion **only from a candidate actually named in live
  diagnostic evidence**. The suggestion never changes `service_name`, a
  correlated Incident's identity, a command, an execution target or a runbook.
  Missing model, timeout or malformed JSON simply leaves identity unresolved.
- The **RemediationPlanner** refuses automatic service start/restart plans when
  the live/source identity is unknown, only observed, conflicted, or does not
  match the target service. This is additive to the existing runbook, approval,
  live revalidation and capability enforcement.

## Operator visibility

The Incident Decision Brief reports `service_identity.status`,
`service_identity.basis` and unverified `suspected_service` separately from
the actual `service`. In Persian, the page says whether the name came from an
alert field, independent MCP evidence, Cognia FQDN mapping, or an unverified
hypothesis. A host-level Incident is labelled a host alert, not as an
unrelated application service.

## QA and operational boundaries

Automated regression coverage:
- Generic CPU/memory/filesystem alerts with an incidental nginx RAG hit.
- Explicit source service precedence and mismatched source/MCP identity.
- Exact FQDN match preserved for read-only discovery.
- Exact-target and exact-service evidence for `verified`.
- LLM grounded candidate selection and hallucination rejection.
- Unknown/observed identity blocked from automatic service remediation.
- Existing Window-style Incident views and Persian provenance.
- Existing approval, runbook and execution acceptance tests are unchanged.

**REAL ENV REQUIRED:** Test this in Windows staging with actual Zabbix/Prometheus/
ELK, MCP, Dotin LLM and Cognia credentials. CI fake/mock backends cannot prove
production signal quality, host identity, or remote action safety.

Deployment (Windows PowerShell, from the project directory):
```powershell
git pull origin main
.\stop-all.ps1
.\start-all.ps1
```
Reload the dashboard with Ctrl+F5. There is no new database migration.

Historical Incident rows (including old, incorrectly named nginx rows) are
**not automatically rewritten**: their Evidence, Approval snapshots, Audit and
Correlation provenance must remain intact until reviewed and corrected through
a controlled audited migration/repair operation.
