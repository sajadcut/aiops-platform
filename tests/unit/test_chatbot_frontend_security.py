from pathlib import Path


def test_chatbot_ui_uses_session_storage_not_persistent_local_storage():
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")
    assert "sessionStorage" in script
    assert "localStorage" not in script
    assert '"X-API-Key"' in script
    assert "sessionStorage.removeItem(KEY_STORAGE)" in script


def test_chatbot_ui_renders_server_text_without_inner_html():
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")
    html = Path("dashboards/chatbot.html").read_text(encoding="utf-8")
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "innerHTML" not in html
    assert "insertAdjacentHTML" not in html


def test_chatbot_api_key_is_not_placed_in_message_payload():
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")
    # The key is confined to the authentication header helper. Chat bodies only
    # contain the user's message/session or an explicit boolean decision.
    assert 'const payload = {message};' in script
    assert 'JSON.stringify({confirm: value})' in script
    assert "api_key" not in script.lower()


def test_chatbot_ui_has_conversation_history_sidebar_without_quick_action_buttons():
    html = Path("dashboards/chatbot.html").read_text(encoding="utf-8")
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")

    assert 'id="sessionList"' in html
    assert 'id="newChat"' in html
    assert 'class="quick-actions"' not in html
    assert "Check VM CPU" not in html
    assert "Check Service Status" not in html
    assert "data-prompt" not in html
    assert 'api("/api/v1/chatbot/sessions"' in script
    assert "selectSession" in script


def test_chatbot_ui_preserves_natural_persian_input_and_bidi_rendering():
    html = Path("dashboards/chatbot.html").read_text(encoding="utf-8")
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")

    assert '<html lang="fa">' in html
    assert "CPU سرور 10.100.6.199 چقدره؟" in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert "فارسی" in script
    # Natural-language input is sent unchanged to the backend/LLM path; there is
    # no client-side keyword router that could make Persian depend on fixed buttons.
    assert 'const payload = {message};' in script
    assert "data-prompt" not in script


def test_chatbot_document_cache_busts_frontend_assets():
    html = Path("dashboards/chatbot.html").read_text(encoding="utf-8")
    assert 'http-equiv="Cache-Control"' in html
    assert 'chatbot.css?v=' in html
    assert 'chatbot.js?v=' in html


def test_chatbot_safe_markdown_renderer_supports_common_llm_formatting_without_html_injection():
    html = Path("dashboards/chatbot.html").read_text(encoding="utf-8")
    assert "function renderInlineMarkdown" in html
    assert 'document.createElement("strong")' in html
    assert 'document.createElement("code")' in html
    assert 'document.createElement("ul")' in html
    assert "innerHTML" not in html
    assert "insertAdjacentHTML" not in html
