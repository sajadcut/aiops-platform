from pathlib import Path


def _script() -> str:
    return Path("dashboards/chatbot.js").read_text(encoding="utf-8")


def _html() -> str:
    return Path("dashboards/chatbot.html").read_text(encoding="utf-8")


def _css() -> str:
    return Path("dashboards/chatbot.css").read_text(encoding="utf-8")


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
    assert "const payload = {message};" in script
    assert "JSON.stringify({confirm: value})" in script
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
    assert "renderSessionSkeleton" in script


def test_chatbot_ui_preserves_natural_persian_input_and_bidi_rendering():
    html = _html()
    script = _script()
    assert '<html lang="fa" dir="rtl">' in html
    assert "CPU سرور 10.100.6.199 چقدره؟" in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert "فارسی" in html or "فارسی" in script or "گفت‌وگو" in html
    assert "const payload = {message};" in script
    assert "data-prompt" not in script


def test_chatbot_ui_supports_english_and_mixed_rtl_ltr_without_client_rewriting():
    html = _html()
    script = _script()
    assert 'id="messageInput"' in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert 'const message = String(rawMessage || "").trim()' in script
    assert "const payload = {message};" in script
    assert "data-prompt" not in script
    assert "10.100.6.199" in html


def test_chatbot_document_cache_busts_frontend_assets():
    html = _html()
    assert 'http-equiv="Cache-Control"' in html
    assert "chatbot.css?v=5" in html
    assert "chatbot.js?v=5" in html


def test_chatbot_safe_markdown_renderer_supports_headings_code_tables_and_lists_without_html_injection():
    script = _script()
    assert "function appendInline" in script
    assert "function renderSafeMarkdown" in script
    assert 'document.createElement("strong")' in script
    assert 'document.createElement("code")' in script
    assert 'document.createElement("table")' in script
    assert 'document.createElement(numbered ? "ol" : "ul")' in script
    assert "headingLevel" in script
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
    assert 'dom.sendButton.setAttribute("aria-label", active ? "توقف پاسخ" : "ارسال پیام")' in script


def test_chatbot_stream_has_no_infinite_spinner_timeout():
    script = _script()
    assert "STREAM_TIMEOUT_MS" in script
    assert "window.setTimeout(() => stopGeneration" in script
    assert "state.streamTimeout" in script
    assert "پاسخ کامل دریافت نشد" in script
    assert "پاسخ متوقف شد" in script


def test_chatbot_product_identity_is_visible_in_login_and_primary_header():
    html = _html()
    assert html.count("NeoBanking Chatbot Operation Platform") >= 3
    assert '<div class="product-title">NeoBanking Chatbot Operation Platform</div>' in html
    assert "Enterprise Operations Copilot" in html
    assert "<title>NeoBanking Chatbot Operation Platform</title>" in html


def test_chatbot_theme_contract_is_tokenized_and_light_mode_is_neutral():
    css = _css()
    assert "--bg-app: #0B0F14;" in css
    assert "--bg-surface: #111720;" in css
    assert "--text-primary: #F4F7FA;" in css
    assert "--accent: #5EA1FF;" in css
    assert ':root[data-theme="light"]' in css
    assert "--bg-app: #F6F8FB;" in css
    assert "--bg-surface: #FFFFFF;" in css
    assert "--text-primary: #17202A;" in css
    assert "--text-secondary: #52606D;" in css
    assert "--accent: #2563EB;" in css
    assert "--accent-hover: #1D4ED8;" in css
    assert "transition: all" not in css.lower()
    assert "linear-gradient" not in css.lower()


def test_chatbot_theme_switch_is_session_scoped_and_accessible():
    script = _script()
    html = _html()
    assert "THEME_STORAGE" in script
    assert "sessionStorage.setItem(THEME_STORAGE, theme)" in script
    assert "localStorage" not in script
    assert 'id="themeToggle"' in html
    assert "تغییر به پوسته" in script


def test_chatbot_composer_and_scroll_behavior_match_operations_chat_contract():
    html = _html()
    script = _script()
    css = _css()
    assert 'id="messageInput"' in html
    assert "Operations Copilot بنویسید" in html
    assert "Shift+Enter" in html
    assert "updateComposerMetrics" in script
    assert "isNearBottom" in script
    assert "updateScrollAffordance" in script
    assert 'dom.messages.addEventListener("scroll", updateScrollAffordance' in script
    assert ".composer:focus-within" in css
    assert ".scroll-bottom" in css


def test_chatbot_tool_proposal_and_error_states_remain_governed_and_compact():
    script = _script()
    css = _css()
    assert "addOperationalFacts" in script
    assert "addDetails" in script
    assert "Action Proposal" in script
    assert "proposal.proposal_id" in script
    assert "JSON.stringify({confirm: value})" in script
    assert "risk_level" in script
    assert ".risk-high" in css
    assert ".error-message" in css
    assert "تلاش مجدد" in script


def test_chatbot_accessibility_and_responsive_contracts_are_present():
    html = _html()
    script = _script()
    css = _css()
    assert 'aria-controls="sidebar"' in html
    assert 'aria-expanded="false"' in html
    assert 'aria-live="polite"' in html
    assert 'aria-label="جست‌وجوی گفت‌وگوها"' in html
    assert 'rename.setAttribute("aria-label"' in script
    assert 'remove.setAttribute("aria-label"' in script
    assert ":focus-visible" in css
    assert "@media (max-width: 880px)" in css
    assert "@media (max-width: 580px)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "transition: transform 160ms ease" in css
