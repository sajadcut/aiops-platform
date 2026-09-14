# Production Acceptance Matrix

Baseline: `MASTER.md 2.4`
Branch: `main` plus the candidate change under review

## Repository-level acceptance

| Requirement | Status | Evidence / gap |
|---|---|---|
| Python + LangGraph core | PASS | E2E graph + durable runtime; full repository test suite is a mandatory promotion gate |
| Context + live Evidence | PASS | Context Builder and governed Zabbix/Elasticsearch/Prometheus/VM/Kubernetes evidence paths; real target acceptance remains external |
| Specialized agents | PASS | Triage plus modular specialist agents |
| RCA + Evaluator gate | PASS | RCA followed by mandatory Evaluator gate |
| Decision / Policy | PASS | Decision Engine + execution policy tests |
| Approval persistence/lifecycle | PASS | PostgreSQL approval store + guarded workflow path; live target validation remains external |
| Audit persistence/redaction | PASS | Audit service + PostgreSQL store + redaction; live production transaction validation remains external |
| Execution boundary | PASS | Tool Registry, validation, durable approval/capability gate and idempotency |
| Runbook governance/dry-run/rollback contracts | PASS | Registry, validator, executor and repository tests; real target execution remains external |
| Verification | PASS | Independent VerificationEngine + post-execution live evidence collection path |
| Operational Memory write-back | PASS | E2E write-back after conclusive verification; remains separate from governed Knowledge RAG |
| Knowledge RAG abstraction | PASS (repo) | `KnowledgeRAGService` fronts Cognia-only; KB/Knowledge/Revision/Chunk traceability is preserved and local pgvector is development/test compatibility only |
| Cognia-only Governed Knowledge RAG | REAL ENV REQUIRED | Repository covers machine auth, separate Client Application scope ID, opaque-token lifecycle, explicit KBs, authoring idempotency, Revision concurrency, Search/Context errors and no-fallback; real endpoint/Application Client/KB grants/Scope/lifecycle/Context acceptance is still required |
| PostgreSQL + pgvector migration lifecycle | PASS (CI) | Dedicated CI acceptance validates migrations/pgvector; pgvector remains required for Operational Memory even when Cognia serves governed Knowledge |
| OIDC/JWT/RBAC | PASS (repo) | Signed JWT/OIDC validation + permission guards; enterprise issuer remains external validation |
| Rate limiting / API guardrails | PASS | Permission guards + strict rate limiting |
| Health/liveness/readiness | PASS (repo) | Repository endpoints; when Cognia is the production provider its readiness is a required dependency |
| Dashboard / incident actions | PASS | PostgreSQL-backed dashboard and remediation action paths; populated production dataset validation remains external |
| Offline Docker/Kubernetes | PASS | Hardened multi-stage Docker/Kubernetes definitions present; external Cognia network reachability must be provided by target environment policy |
| Image attestation workflow | PASS | Trivy/SBOM/cosign container acceptance is green in repository CI; real internal registry signing/promotion remains external |
| Repository hygiene | PASS | Hygiene automation and CI guard present |
| CI unit/integration/scenario tests | PASS when current HEAD is green | Promotion must use the exact current commit's CI result |
| CI database acceptance | PASS when current HEAD is green | Real pgvector container path remains part of CI |

## External validation required

1. Real Cognia Application Client authentication over the target environment's approved HTTPS endpoint.
2. Search against the exact assigned Knowledge Base IDs with valid and invalid grants, including all-or-nothing authorization behavior.
3. Cognia Scope validation for General / ClientApplication / ExternalSubject when those scopes are used by AIOps Knowledge.
4. Cognia Search dependency/index failure behavior and AIOps no-fallback observability.
5. Cognia Context Generation, `isSufficient` handling and traceability if a Context Profile is configured for AIOps.
6. Real enterprise Zabbix/Elasticsearch/Prometheus endpoint acceptance.
7. Real least-privilege VM/Kubernetes remediation and recovery.
8. Real runbook execution, rollback and idempotency against controlled targets.
9. Real enterprise OIDC issuer/JWKS and role mapping.
10. Internal registry image signing, verification and immutable promotion.
11. Offline/restricted-network installation and recovery test in the target network, including the explicitly approved network path to Cognia if Cognia is external to the AIOps namespace.

## Verdict rule

Repository-level Production Ready is allowed only when all CI jobs are green and no repository-level blocker remains. Overall external Production Ready remains blocked until the explicitly listed target-environment validations have evidence. Cognia repository contract tests are not a substitute for real KB grants, Scope behavior or Context/Search execution against the deployed service.
