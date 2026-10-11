# Cognia AIOps handover and runtime acceptance

Source contract: Cognia AIOps handover (26 Sep 2026) and the team's consumer Postman collection.
This document contains **no credentials**. Do not commit the handover PDF, Postman Environment
with Current Values, machine credentials, human password, or acquired access tokens.

## Configure on the Windows AIOps application server

Set the deployment's private `.env` (not `.env.example` or Git):

```dotenv
COGNIA_BASE_URL=http://cogniaapi.sandpod.ir
COGNIA_CLIENT_ID=<obtain from the private handover/secret store>
COGNIA_CLIENT_SECRET=<obtain from the private handover/secret store>
COGNIA_CLIENT_APPLICATION_ID=2
COGNIA_KNOWLEDGE_BASE_IDS=[1]
COGNIA_CONTEXT_PROFILE_ID=
COGNIA_TIMEOUT_SECONDS=15
```

- Cognia KB **AIOps**, ID **1**, is active according to the handover.
- Client Application **AIOps**, *numeric ID 2*, is separate from the opaque `clientId`
  used in the machine token request. Never put the numeric ID into `COGNIA_CLIENT_ID`.
- The machine identity has `kb.read` and `kb.contribute` according to the
  handover; live grants still require verification.
- No Context Profile has been provisioned. **Leave `COGNIA_CONTEXT_PROFILE_ID` blank.**
  Search is usable without Context Generation. Do not invent a Profile ID.
- External Subject namespace/identifier semantics have not been agreed.
  Do not fabricate Subject context from a service name, hostname, or customer.
- The declared KB approval policy is `none`, but the machine identity cannot
  perform human-only approval operations; do not bypass the normal AIOps
  governed execution/approval model.
- The handover's service URL uses **unencrypted HTTP**. This carries machine
  credentials and Bearer tokens in cleartext on the transport path. Obtain a
  trusted **HTTPS** endpoint from the Cognia team before production; assess
  certificate validation separately because the current AIOps HTTP transport
  disables TLS certificate verification. No claim of production transport
  security is made here.

## Read-only acceptance on the application server

After securely populating `.env` and restarting AIOps, run from the repository root:

```powershell
python -m scripts.verify_cognia_connection --query "gfpapi systemd service runbook"
```

The command uses the same `CogniaClient` and Cognia settings as the application.
It makes only these calls:

1. `POST /api/access/client-auth/token` — Machine Client auth. This call
   obtains a temporary opaque token; nothing is registered/changed.
2. `GET /api/engine/knowledge-bases/1` — read and verify exact KB identity,
   activity and grants visible to the configured Client Application.
3. `POST /api/engine/search` — **read-only Search** with explicit
   `knowledgeBaseIds: [1]`, limit 5; no Subject is inferred.

It outputs a redacted JSON report with `auth`, `knowledge_bases`, and `search`
statuses; it never prints raw tokens, client credentials, KB content, or query
contents. It never invokes Knowledge Registration, Revision Creation, Approve,
Reject, maintenance, or the Postman collection's state-changing requests.

Exit codes: 0 for successful authentication, KB metadata read and Search API,
including `status: empty`; 2 for configuration/auth/authorization/contract/
transport failures; 3 for successful-but-empty Search when requested with
`--require-results`.

Use `--require-results` only after the Cognia team has confirmed that at least
one authorized **Activated** knowledge revision is indexed for your test query.
An empty Search is not the same as a failed auth or failed provider.

```powershell
python -m scripts.verify_cognia_connection --query "gfpapi" --require-results
```

Use `--test-context` **only after** a real Context Profile has been provisioned
and `COGNIA_CONTEXT_PROFILE_ID` configured. Missing Profile does not block
Search. An insufficient context package is reported as `insufficient`, not
as sufficient, and no empty package is made into fabricated RAG evidence.

## Contract mapping and remaining acceptance gates

| Contract | Repository | Status |
| --- | --- | --- |
| Machine Client token + expiry/401 refresh | `integrations/cognia/client.py` | Implemented; live acceptance required |
| Explicit KB identity/read authorization | `CogniaClient.get_knowledge_base` and smoke probe | Implemented; live acceptance required |
| Search with explicit KB list, opaque continuation, grants and Scope | `CogniaClient.search`, `apps/rag_service` | Implemented; activation/indexed-result test required |
| Subject isolation | `_normalize_scope_context` and API scope guard | Guarded; no untrusted subject inference |
| Knowledge Registration with Idempotency-Key | `CogniaClient.register_knowledge` | Implemented; **not executed by probe** |
| Revision optimistic concurrency + processing status | `CogniaClient.create_revision`, `get_processing_status` | Implemented; live acceptance required |
| Human approve/reject | Not exposed by Machine Client | Intentionally unavailable |
| Context Generation | `CogniaClient.generate_context` | Implemented; **disabled until Profile configured** |
| Backend reachable + credentials valid + KB readable | `scripts/verify_cognia_connection.py` | Read-only verification available |

**Live environment required** before declaring Cognia Production PASS:
verify machine secret rotation, exact KB grants, positive and negative
authorization, activated/retrievable indexed knowledge, scoped-result
isolation if applicable, RAG outage fail-closed behavior, and secure
TLS for credentials. The original handover explicitly did not test
registration, revision creation, processing, or Context Generation.
Do not treat the Postman collection as proof of those live operations;
the collection warns against running the entire Runner indiscriminately.
