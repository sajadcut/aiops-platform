# Production Acceptance Matrix

Baseline: `MASTER.md 2.5 - Cognia-Only Knowledge RAG`
Branch: `main`

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
| Cognia-only Knowledge RAG boundary | PASS (repo contract) | `KnowledgeRAGService` has one retrieval boundary: Cognia. KB/Knowledge/Revision/Chunk traceability is preserved; there is no runtime provider switch or PostgreSQL/pgvector Knowledge retriever |
| Cognia real environment | REAL ENV REQUIRED | Repository covers machine auth, separate Client Application scope ID, opaque-token lifecycle, explicit KBs, authoring idempotency, Revision concurrency, Search/Context errors and no alternate-RAG fallback; real endpoint/Application Client/KB grants/Scope/lifecycle/Context acceptance is still required |
| PostgreSQL + pgvector migration lifecycle | PASS when current HEAD is green | pgvector is validated only for Operational Memory; the active local Knowledge vector path is retired and historical content is non-RAG archive only |
| OIDC/JWT/RBAC | PASS (repo) | Signed JWT/OIDC validation + permission guards; enterprise issuer remains external validation |
| Rate limiting / API guardrails | PASS | Permission guards + strict rate limiting |
| Health/liveness/readiness | PASS (repo) | Repository endpoints; Cognia readiness is a required Production dependency because Cognia is the sole Knowledge RAG |
| Dashboard / incident actions | PASS | PostgreSQL-backed dashboard and remediation action paths; populated production dataset validation remains external |
| Offline Docker/Kubernetes | PASS | Hardened multi-stage Docker/Kubernetes definitions present; external Cognia network reachability must be provided by target environment policy |
| Image attestation workflow | PASS when current HEAD is green | Trivy/SBOM/cosign container acceptance must be green on the exact promotion commit; real internal registry signing/promotion remains external |
| Repository hygiene | PASS | Hygiene automation and CI guard present |
| CI unit/integration/scenario tests | PASS when current HEAD is green | Promotion must use the exact current commit's CI result |
| CI database acceptance | PASS when current HEAD is green | Real PostgreSQL/pgvector Operational-Memory path remains part of CI |

## External validation required

1. Real Cognia Application Client authentication over the target environment's approved HTTPS endpoint.
2. Search against the exact assigned Knowledge Base IDs with valid and invalid grants, including all-or-nothing authorization behavior.
3. Cognia Scope validation for General / ClientApplication / ExternalSubject when those scopes are used by AIOps Knowledge.
4. Cognia lifecycle validation from registration through Approval where required, Processing, Activated and Searchable state.
5. Cognia Search dependency/index failure behavior and AIOps explicit degradation with no second RAG.
6. Cognia Context Generation, `isSufficient` handling and traceability if a Context Profile is configured for AIOps.
7. Real enterprise Zabbix/Elasticsearch/Prometheus endpoint acceptance.
8. Real least-privilege VM/Kubernetes remediation and recovery.
9. Real runbook execution, rollback and idempotency against controlled targets.
10. Real enterprise OIDC issuer/JWKS and role mapping.
11. Internal registry image signing, verification and immutable promotion.
12. Offline/restricted-network installation and recovery test in the target network, including the explicitly approved network path to Cognia if Cognia is external to the AIOps namespace.

## Verdict rule

Repository-level Production Ready is allowed only when all mandatory CI jobs are green on the exact promotion HEAD and no repository-level blocker remains. Overall external Production Ready remains blocked until the explicitly listed target-environment validations have evidence. Cognia repository contract tests are not a substitute for real KB grants, Scope behavior, lifecycle, Context or Search execution against the deployed service.
