# NeoBanking Chatbot UI v3

The `/chatbot` experience is a conversation-first Enterprise Operations Copilot workspace. The v3 frontend preserves the existing API-key authentication, RBAC, MCP-only infrastructure boundary, durable action proposal/approval flow, replay protection, audit behavior and safe DOM-only rendering.

## Interaction model

- Collapsible conversation sidebar with search, date grouping, pin/unpin and existing rename/delete actions.
- Modern empty state with prompt-only Quick Ops; mutating actions such as restart only prepare a governed request and do not bypass approval.
- Slash shortcuts (`/vm`, `/k8s`, `/pods`, `/service`, `/health`, `/incident`, `/help`) populate the normal composer and therefore use the same backend path and governance.
- `Ctrl/Cmd + K` command palette for common workspace actions and Quick Ops.
- Optional context/activity panel only renders data actually available in the authenticated UI session; it does not synthesize environment or MCP readiness.
- User edit/re-submit, assistant regenerate/details/collapse, safe HTTP(S) linkification, operational fact cards, compact tool activity and existing action proposal controls.
- Dark-first neutral visual system with a separately tuned neutral light theme, responsive sidebar/context drawers and reduced-motion support.

## Streaming truth

The browser continues to use the existing SSE endpoint and AbortController cancellation. The currently verified Dotin integration is request/response oriented: the server emits heartbeat/status events while waiting and presentation deltas after a complete validated provider result. UI v3 does not claim provider-native token streaming.

## Security invariants

- API key remains in browser `sessionStorage`, never `localStorage` or the message payload.
- Server/model text is rendered with DOM nodes; `innerHTML` and `insertAdjacentHTML` are not used for untrusted content.
- Link enhancement accepts only `http://` and `https://` text and opens external links with `noopener noreferrer`.
- Quick actions, slash commands, edit/retry and command-palette operations feed the normal chat/API path. They do not execute infrastructure operations directly.
- Backend-provided proposal risk and approval behavior remains authoritative.

## Real-environment acceptance

Repository tests cannot prove private infrastructure. Provider-native streaming/cancellation behavior at the real Dotin gateway, VM MCP + SSH-backed operations against an authorized VM, Kubernetes MCP operations in the assigned namespace, and deployment-specific proxy/network behavior remain **REAL ENV REQUIRED**.
