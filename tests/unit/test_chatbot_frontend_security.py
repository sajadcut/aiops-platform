from pathlib import Path


def _script() -> str:
    return Path("dashboards/chatbot.js").read_text(encoding="utf-8")


def _html() -> str:
    return Path("dashboards/chatbot.html").read_text(encoding="utf-8")


def test_chatbot_ui_uses_session_storage_not_persistent_local_storage():
    script = _script()
    assert "sessionStorage" in script
    assert "localStorage" not in script
    assert '"X-API-Key"' in script
    assert "sessionStorage.removeItem(KEY_STORAGE)" in script


def test_chatbot_ui_renders_server_text_without_unsafe_html_injection():
    script = _script()
    html = _html()
    assert "textContent" in script
    assert "document.createTextNode" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "innerHTML" not in html
    assert "insertAdjacentHTML" not in html


def test_chatbot_api_key_is_not_placed_in_message_payload():
    script = _script()
    assert 'const payload = {message};' in script
    assert 'JSON.stringify({confirm: value})' in script
    assert "api_key" not in script.lower()


def test_chatbot_ui_has_modern_history_controls_without_quick_action_buttons():
    html = _html()
    script = _script()
    assert 'id="sessionList"' in html
    assert 'id="sessionSearch"' in html
    assert 'id="newChat"' in html
    assert 'id="renameDialog"' in html
    assert 'id="deleteDialog"' in html
    assert 'class="quick-actions"' not in html
    assert "Check VM CPU" not in html
    assert "Check Service Status" not in html
    assert "data-prompt" not in html
    assert 'api("/api/v1/chatbot/sessions"' in script
    assert "selectSession" in script
    assert 'method: "PATCH"' in script
    assert 'method: "DELETE"' in script


def test_chatbot_ui_preserves_natural_persian_input_and_bidi_rendering():
    html = _html()
    script = _script()
    assert '<html lang="fa" dir="rtl">' in html
    assert "CPU سرور 10.100.6.199 چقدره؟" in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert "فارسی" in html or "فارسی" in script
    assert 'const payload = {message};' in script
    assert "data-prompt" not in script


def test_chatbot_ui_supports_english_and_mixed_rtl_ltr_without_client_rewriting():
    html = _html()
    script = _script()
    # Conversation/message bodies and the composer use browser bidi isolation so
    # English, Persian, IPs and commands can coexist without a keyword router.
    assert 'id="messageInput"' in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert 'const payload = {message};' in script
    assert "message.trim()" in script
    assert "data-prompt" not in script
    assert "10.100.6.199" in html


def test_chatbot_document_cache_busts_frontend_assets():
    html = _html()
    assert 'http-equiv="Cache-Control"' in html
    assert 'chatbot.css?v=4' in html
    assert 'chatbot.js?v=4' in html


def test_chatbot_safe_markdown_renderer_supports_code_tables_and_lists_without_html_injection():
    script = _script()
    assert "function appendInline" in script
    assert "function renderSafeMarkdown" in script
    assert 'document.createElement("strong")' in script
    assert 'document.createElement("code")' in script
    assert 'document.createElement("table")' in script
    assert 'document.createElement(numbered ? "ol" : "ul")' in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script


def test_chatbot_frontend_uses_stream_transport_stop_and_terminal_error_states():
    html = _html()
    script = _script()
    assert "/api/v1/chatbot/message/stream" in script
    assert "text/event-stream" in script
    assert "AbortController" in script
    assert "stopGeneration" in script
    assert "renderTerminalError" in script
    assert "stream_ended_without_terminal_event" in script
    assert 'class="stop-icon hidden"' in html


def test_chatbot_stream_has_no_infinite_spinner_timeout():
    script = _script()
    assert "STREAM_TIMEOUT_MS" in script
    assert "window.setTimeout(() => stopGeneration" in script
    assert "state.streamTimeout" in script
