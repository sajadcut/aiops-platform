# Operations Copilot v2

Operations Copilot v2 is the operator-facing chat surface for the governed AIOps control plane. The redesign keeps the existing authentication, RBAC, semantic-tool allowlist, MCP boundary, durable approval, binding, consume-before-execute, verification and audit controls unchanged while replacing the demo-like chat experience with a modern operational workspace.

## Runtime contract

The browser uses `POST /api/v1/chatbot/message/stream` as its primary transport. The endpoint is Server-Sent Events over an authenticated POST request and emits a small event vocabulary:

- `session`: durable session/request identity is established;
- `status` / `heartbeat`: bounded progress feedback while the backend is working;
- `answer_start`: validated response metadata and governed tool/source information;
- `delta`: user-visible response text chunks;
- `complete`: the successful terminal outcome;
- `error`: a short typed terminal failure.

The existing `POST /api/v1/chatbot/message` endpoint remains supported for backward compatibility.

### Provider streaming note

The supplied Dotin General Chatbot contract documents the `stream` request option, but the existing AIOps adapter is request/response oriented and does not have a verified provider-stream parser. v2 therefore does **not** pretend that native provider token streaming exists. While the provider call is in flight, the SSE transport sends heartbeats so the UI never appears frozen. After a complete validated response is available, the backend emits bounded `delta` chunks for the ChatGPT-style typewriter presentation.

Provider-native token streaming is **REAL ENV REQUIRED**: enable it only after the actual gateway's event format, tool-call streaming semantics, cancellation behavior and timeout behavior are verified. The browser/SSE `delta` contract can forward native chunks later without changing the UI contract.

## No-silent-request invariant

The interactive chat surface enforces this invariant:

> Every submitted operator message reaches a visible terminal state: complete answer/tool result/action proposal, or a short error.

The browser has a hard request timeout and treats a stream that closes without `complete` or `error` as a failure. The server emits a typed terminal error for LLM/tool failures and persists a short failed assistant event when possible. Partial generated prefixes are not treated as successful answers.

The direct chatbot LLM stage receives one bounded repair attempt for an obviously incomplete prose prefix. Tool calls are not replayed after execution; the repair happens before any governed tool is invoked.

## Operator-safe errors

Raw exceptions and tracebacks never render in the conversation. Representative messages are intentionally short:

- `LLM پاسخ نداد. دوباره تلاش کنید.`
- `MCP پاسخ نداد. دوباره تلاش کنید.`
- `درخواست به دلیل Timeout کامل نشد.`
- `دسترسی کافی ندارید.`
- `خطای موقت در دیتابیس.`

Structured logs retain the technical error type plus request/correlation/session context under the existing redaction policy.

## Conversation UX

The v2 interface adds:

- NOC-friendly dark design plus light mode;
- responsive desktop/mobile sidebar;
- durable conversation titles derived from the first operator turn;
- search, rename and delete/archive conversation controls;
- draft preservation while switching sessions in the same browser tab;
- Stop generation and retry failed message controls;
- copy answer and copy code actions;
- safe DOM-only Markdown rendering for lists, tables, code blocks, inline code and emphasis;
- tool/source badges and collapsible governed source details;
- modern approval cards without weakening the proposal/approval API;
- automatic RTL/LTR behavior for Persian, English, IPs and mixed operational text.

The API key remains in `sessionStorage` only and is never put into a chat message or durable history.

## Persistence and migration

Migration `g4d5e6f7a8b9` adds `title` and `archived_at` to `chat_sessions`. Deleting a conversation from the UI erases its chat messages and archives the session. It intentionally does not cascade-delete governed action proposals because those records belong to the operational approval/audit boundary.

After pulling this release locally:

```powershell
alembic -c .\database\migrations\alembic.ini upgrade head
```

## Acceptance

Repository-level tests cover the modern frontend safety contract, SSE terminal-outcome contract, short error taxonomy, bounded incomplete-response repair, rate limiting, session title/rename/archive behavior and the existing durable mutation governance tests.

The following remain environment acceptance rather than repository PASS claims:

- native Dotin provider token streaming: **REAL ENV REQUIRED**;
- real Dotin timeout/cancellation behavior: **REAL ENV REQUIRED**;
- VM MCP / SSH read and write execution against a managed VM: **REAL ENV REQUIRED**;
- Kubernetes MCP operations against the target namespace: **REAL ENV REQUIRED**.
