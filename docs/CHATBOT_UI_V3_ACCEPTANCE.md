# Chatbot UI v3 acceptance notes

## Repository-verifiable

- Modern three-area operator workspace shell: conversation sidebar, primary chat workspace, optional context/activity panel.
- Prompt-only Quick Ops and slash shortcuts route through the normal composer/API path.
- Existing SSE/AbortController, session history, action proposal decision endpoint and safe Markdown renderer are preserved.
- UI enhancements use `textContent`, `createTextNode` and DOM APIs rather than unsafe HTML insertion.
- API key storage remains session-scoped.
- Persian/English/IP mixed-direction handling uses `dir="auto"`, LTR code rendering and `unicode-bidi` isolation/plaintext rules.
- Responsive drawer layouts, focus-visible styles and reduced-motion behavior are present.

## Visual QA note

Automated contract tests cover the frontend structure and safety invariants. Pixel-level browser screenshot validation is environment-dependent and must not be represented as passed unless a working browser runtime renders the page successfully.

## REAL ENV REQUIRED

- Dotin provider-native token/event streaming and true upstream cancellation at the real gateway.
- Authorized VM MCP + SSH-backed read/write behavior.
- Kubernetes MCP operations inside the assigned production-like namespace.
- Deployment-specific proxy, buffering and network behavior outside GitHub-hosted CI.
