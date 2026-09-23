# Dotin General Chatbot integration

This document records the AIOps consumer-side contract for the supplied **General Chatbot** OpenAI-compatible API documentation dated 15 September 2026.

## Runtime configuration

Use the dedicated provider name so the project applies the documented Dotin contract instead of generic OpenAI-compatible behavior:

```env
LLM_PROVIDER=dotin-general-chatbot
LLM_BASE_URL=https://aifa-chatbot.dev.dotin.ir
LLM_API_KEY=<token-value-only>
LLM_MODEL=assistance-model
LLM_TIMEOUT_SECONDS=60
```

`LLM_MODEL` must be either `assistance-model` or `developer-model`.

`LLM_API_KEY` is the Bearer token value only. The adapter adds the `Bearer ` prefix itself. Never commit the real token.

`LLM_BASE_URL` may be the service root, a `/v1` base URL, or the full `/v1/chat/completions` endpoint. The canonical request target is:

```text
POST /v1/chat/completions
```

HTTP and HTTPS remain supported by the AIOps transport policy. HTTPS server-certificate/hostname validation is intentionally disabled by the project-wide transport policy.

## Headers

Every Dotin request includes:

```text
Authorization: Bearer <token>
Content-Type: application/json
x-request-id: <request-id>
x-session-id: <session-id>
x-user-id: <user-id>
```

Callers may pass `request_id`, `session_id` and `user_id` to the adapter. If they do not, AIOps generates a unique request id, uses it as the single-call session id, and identifies the caller as `aiops-platform`.

## Request options

The adapter sends normal OpenAI-compatible `model`, `messages`, `temperature` and `max_tokens` fields and supports the Dotin-specific documented options:

- `enable_thinking`: boolean, default `false`.
- `stream`: the supplied API documents a boolean default of `false`. The current AIOps `LLMAdapter` is request/response oriented, so `stream=true` is rejected explicitly rather than silently mishandled.
- `reasoning_effort`: `low`, `medium`, `high`, `xhigh`, `max`, or `xmax`; default `medium`.
- `tools`: array of OpenAI-style function definitions.
- `tool_choice`: supports `none`, `auto`, `required`, a forced function object, or an `allowed_tools` object.

Example adapter call:

```python
response = await llm.generate_with_messages(
    [{"role": "user", "content": "Analyze the incident"}],
    enable_thinking=True,
    reasoning_effort="high",
    request_id="req-123",
    session_id="incident-456",
    user_id="aiops-platform",
)
```

## Tool-call boundary

The supplied General Chatbot contract can return `finish_reason=tool_calls` with `message.tool_calls`. AIOps preserves those values in `LLMResponse.finish_reason` and `LLMResponse.tool_calls`.

The LLM adapter **does not execute function calls**. Tool-call output is model output only. AIOps operational reads/writes continue through the canonical MCP/tool registry, deterministic policy, approval and execution-capability boundaries. This prevents an LLM function call from bypassing execution governance.

## Response handling

Normal text responses populate `LLMResponse.content`. Tool-call responses may legitimately have an empty content string; they are not converted to the literal string `"None"`.

The raw provider body remains available in `LLMResponse.raw_response`, including provider `id`, `choices`, `usage` and other OpenAI-compatible fields.

Transient gateway failures use the shared bounded retry policy:
`RETRY_MAX_ATTEMPTS`, `RETRY_DELAY_SECONDS` and
`RETRY_BACKOFF_FACTOR`. Only HTTP 408, 429, 5xx responses and transport/timeout
failures are retried. Non-transient 4xx responses fail immediately. The
`x-request-id` remains stable across transport retries so the upstream gateway
can correlate a single logical request.

This transport retry is separate from completion repair. Completion repair only
regenerates incomplete/truncated model output and remains disabled for
tool-enabled chat. Transport retry can occur before any valid model response
exists; the adapter still never executes model-proposed tools, so Policy,
Approval and ExecutionService remain authoritative.

## Acceptance coverage

`tests/unit/test_dotin_general_chatbot_llm.py` covers:

- canonical `/v1/chat/completions` URL construction;
- Bearer authentication and required tracking headers;
- `assistance-model` and `developer-model` validation;
- default and explicit thinking/reasoning options;
- tool definition and `tool_choice` forwarding;
- `finish_reason=tool_calls` response preservation;
- explicit rejection of unsupported streaming mode and invalid contract values;
- provider selection through `configured_llm_adapter()`;
- bounded retry of transient HTTP 500/transport failures;
- immediate failure without retry for non-transient HTTP 400 responses.
