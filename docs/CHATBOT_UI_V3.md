# NeoBanking Chatbot Operation Platform UI v3

The `/chatbot` experience is a conversation-first Enterprise Operations Copilot workspace for NOC/SRE workflows. The primary product identity is **NeoBanking Chatbot Operation Platform** and assistant messages use **Operations Copilot**.

## Interaction model

- Compact collapsible conversation sidebar with New Chat, client-side search, active state, rename/delete controls and mobile drawer behavior.
- Centered conversation column with bounded width, subtle user surfaces and open assistant responses rather than heavy messenger bubbles.
- Non-clickable capability badges in the empty state: VM, Kubernetes, Zabbix, Logs and Service Health.
- Sticky auto-growing composer with Enter-to-send, Shift+Enter newline, disabled empty send and AbortController-backed Stop.
- Smart scrolling only keeps the viewport pinned while the operator is already near the latest message.
- Compact operational facts for tool results with raw structured data available only under Details.
- Explicit Action Proposal cards continue to use the existing backend decision endpoint and approval/replay protections.
- Compact error cards keep public messages short and may surface safe Request ID, Component, Code and Timestamp metadata.

## Theme system

Dark mode is the operations-first default palette. Light mode is independently designed with neutral white/gray surfaces and dark body text; blue is reserved for actions, focus and limited accents.

Theme preference is a non-secret UI preference stored in `localStorage` and the first visit respects `prefers-color-scheme`. The API key remains strictly in `sessionStorage`.

## Frontend architecture

The UI remains framework-free and dependency-light:

- `chatbot.js`: state, session/history, dialogs, composer and orchestration UI.
- `chatbot-ui.js`: theme, safe Markdown, message rendering helpers, tool facts and error metadata.
- `chatbot-transport.js`: authenticated API transport and SSE parsing.

The browser never executes model-provided HTML. Markdown is rendered with DOM nodes and code blocks are always LTR.

## Streaming truth

The browser uses the existing SSE endpoint and AbortController cancellation.

The currently verified Dotin integration is request/response oriented: the server emits heartbeat/status events while waiting and bounded presentation deltas after a complete validated provider response. This UI does **not** claim provider-native token streaming.

## Security invariants

The redesign does not bypass or weaken:

- Authentication and RBAC
- semantic tool allowlisting
- MCP-only VM/Kubernetes infrastructure boundaries
- durable approval and exact-intent binding
- consume-before-execute and replay protection
- post-execution verification and audit logging
- prompt-injection controls and secret redaction

The API key is never stored in `localStorage`, never inserted into the message payload and never rendered into chat history.

## Acceptance

Repository regression coverage locks:

- dark/light theme and neutral light-mode text/surfaces
- theme persistence and system preference
- Persian/English/mixed RTL/LTR handling
- safe Markdown/XSS behavior
- streaming complete/interrupted/timeout/Stop/no-silent-request contracts
- History/New Chat/rename/delete/search
- API key sessionStorage-only behavior and show/hide UX
- Action Proposal UI and existing approval/replay backend acceptance
- responsive/collapsed sidebar behavior
- reduced-motion and keyboard/focus accessibility contracts

## REAL ENV REQUIRED

Repository tests cannot prove private infrastructure. These remain **REAL ENV REQUIRED**:

- provider-native Dotin token streaming/cancellation at the real gateway
- VM MCP + SSH-backed operations against an authorized VM
- Kubernetes MCP operations in the assigned namespace
- deployment-specific proxy/network behavior
- final visual review in the organization's target browsers and display environment
