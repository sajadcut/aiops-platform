from pathlib import Path


def _script() -> str:
    return Path("dashboards/chatbot.js").read_text(encoding="utf-8")


def _ui_script() -> str:
    return Path("dashboards/chatbot-ui.js").read_text(encoding="utf-8")


def _html() -> str:
    return Path("dashboards/chatbot.html").read_text(encoding="utf-8")


def _css() -> str:
    return Path("dashboards/chatbot.css").read_text(encoding="utf-8")


def _main() -> str:
    return Path("apps/api/main.py").read_text(encoding="utf-8")


def test_chatbot_api_key_is_session_only_while_non_secret_ui_preferences_are_persistent():
    script = _script()
    ui = _ui_script()
    combined = script + ui
    assert "sessionStorage.setItem(KEY_STORAGE" in script
    assert "sessionStorage.removeItem(KEY_STORAGE)" in script
    assert "localStorage.setItem(KEY_STORAGE" not in combined
    assert "localStorage.getItem(KEY_STORAGE" not in combined
    assert 'localStorage.setItem(THEME_STORAGE' in ui
    assert 'localStorage.setItem(SIDEBAR_STORAGE' in script
    assert '"X-API-Key"' in script


def test_chatbot_ui_renders_server_text_without_unsafe_html_injection():
    combined = _script() + _ui_script()
    html = _html()
    assert "textContent" in combined
    assert "document.createTextNode" in combined
    assert "innerHTML" not in combined
    assert "insertAdjacentHTML" not in combined
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
    assert 'id="sidebarCollapse"' in html
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
    assert "setSidebarCollapsed" in script


def test_chatbot_ui_preserves_natural_persian_input_and_bidi_rendering():
    html = _html()
    script = _script()
    assert '<html lang="fa" dir="rtl">' in html
    assert "درباره وضعیت زیرساخت یا سرویس‌ها سؤال کنید" in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert "فارسی" in html
    assert "const payload = {message};" in script
    assert "data-prompt" not in script


def test_chatbot_ui_supports_english_and_mixed_rtl_ltr_without_client_rewriting():
    html = _html()
    script = _script()
    ui = _ui_script()
    assert 'id="messageInput"' in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert 'const message = String(rawMessage || "").trim()' in script
    assert "const payload = {message};" in script
    assert "data-prompt" not in script
    assert 'code.setAttribute("dir", "ltr")' in ui
    assert "10.100.6.199" not in html


def test_chatbot_document_cache_busts_module_assets_and_api_serves_helper():
    html = _html()
    main = _main()
    assert 'http-equiv="Cache-Control"' in html
    assert "chatbot.css?v=6" in html
    assert 'type="module"' in html
    assert "chatbot.js?v=6" in html
    assert '"/chatbot/chatbot-ui.js"' in main
    assert '"chatbot-ui.js"' in main


def test_chatbot_safe_markdown_renderer_is_modular_and_xss_safe():
    script = _script()
    ui = _ui_script()
    assert 'from "./chatbot-ui.js?v=6"' in script
    assert "function appendInline" in ui
    assert "export function renderSafeMarkdown" in ui
    assert 'document.createElement("strong")' in ui
    assert 'document.createElement("code")' in ui
    assert 'document.createElement("table")' in ui
    assert 'document.createElement(numbered ? "ol" : "ul")' in ui
    assert "headingLevel" in ui
    assert "innerHTML" not in ui
    assert "insertAdjacentHTML" not in ui


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
    assert 'showStatus("در حال نوشتن پاسخ…"' in script


def test_chatbot_stream_has_no_infinite_spinner_timeout_and_empty_send_is_disabled():
    script = _script()
    html = _html()
    assert "STREAM_TIMEOUT_MS" in script
    assert "window.setTimeout(() => stopGeneration" in script
    assert "state.streamTimeout" in script
    assert "پاسخ کامل دریافت نشد" in script
    assert "پاسخ متوقف شد" in script
    assert 'id="sendButton"' in html
    assert "disabled" in html
    assert "dom.sendButton.disabled" in script


def test_chatbot_product_identity_is_visible_in_login_and_primary_header():
    html = _html()
    assert html.count("NeoBanking Chatbot Operation Platform") >= 3
    assert '<div class="product-title">NeoBanking Chatbot Operation Platform</div>' in html
    assert "AI-Powered Operations Copilot" in html
    assert "<title>NeoBanking Chatbot Operation Platform</title>" in html


def test_chatbot_light_theme_is_neutral_and_does_not_use_blue_message_background():
    css = _css()
    assert "--bg-app: #0B0F14;" in css
    assert "--text-primary: #F4F7FA;" in css
    assert ':root[data-theme="light"]' in css
    assert "--bg-app: #F6F8FB;" in css
    assert "--bg-surface: #FFFFFF;" in css
    assert "--text-primary: #17202A;" in css
    assert "--text-secondary: #52606D;" in css
    assert "--accent: #315FAD;" in css
    assert "--user-surface: #EEF1F4;" in css
    assert ':root[data-theme="light"] .message.user .message-card' in css
    assert "background: var(--user-surface);" in css
    assert "color: var(--text-primary);" in css
    assert "transition: all" not in css.lower()


def test_chatbot_theme_switch_uses_local_storage_system_preference_and_labeled_control():
    html = _html()
    script = _script()
    ui = _ui_script()
    assert 'id="themeToggle"' in html
    assert 'id="themeIcon"' in html
    assert 'id="themeLabel"' in html
    assert "initialTheme()" in script
    assert "prefers-color-scheme: light" in ui
    assert "localStorage.getItem(THEME_STORAGE)" in ui
    assert "localStorage.setItem(THEME_STORAGE" in ui
    assert "sessionStorage.setItem(THEME_STORAGE" not in script + ui


def test_api_key_show_hide_does_not_change_storage_boundary():
    html = _html()
    script = _script()
    assert 'id="apiKeyToggle"' in html
    assert 'type="password"' in html
    assert "toggleApiKeyVisibility" in script
    assert 'dom.apiKeyInput.type = visible ? "password" : "text"' in script
    assert "sessionStorage.setItem(KEY_STORAGE" in script


def test_chatbot_composer_and_scroll_behavior_match_operations_chat_contract():
    html = _html()
    script = _script()
    css = _css()
    assert 'id="messageInput"' in html
    assert "درباره وضعیت زیرساخت یا سرویس‌ها سؤال کنید" in html
    assert "Shift+Enter" in html
    assert "updateComposerMetrics" in script
    assert "isNearBottom" in script
    assert "updateScrollAffordance" in script
    assert 'dom.messages.addEventListener("scroll", updateScrollAffordance' in script
    assert ".composer:focus-within" in css
    assert ".scroll-bottom" in css


def test_chatbot_tool_proposal_and_error_states_remain_governed_and_compact():
    script = _script()
    ui = _ui_script()
    css = _css()
    assert "addOperationalFacts" in script
    assert "addDetails" in script
    assert "addErrorMeta" in script
    assert "Action Proposal" in script
    assert "proposal.proposal_id" in script
    assert "JSON.stringify({confirm: value})" in script
    assert "risk_level" in script
    assert ".risk-high" in css
    assert ".error-message" in css
    assert ".error-meta" in css
    assert "تلاش مجدد" in script
    assert "Request" in ui and "Component" in ui and "Code" in ui


def test_chatbot_sidebar_has_desktop_collapse_and_mobile_drawer_contracts():
    html = _html()
    script = _script()
    css = _css()
    assert 'id="sidebarCollapse"' in html
    assert 'aria-expanded="true"' in html
    assert "setSidebarCollapsed" in script
    assert "SIDEBAR_STORAGE" in script
    assert ".workspace.sidebar-collapsed" in css
    assert "@media (min-width: 881px)" in css
    assert "@media (max-width: 880px)" in css


def test_chatbot_accessibility_and_responsive_contracts_are_present():
    html = _html()
    script = _script()
    css = _css()
    assert 'aria-controls="sidebar"' in html
    assert 'aria-live="polite"' in html
    assert 'aria-busy="false"' in html
    assert 'aria-label="جست‌وجوی گفت‌وگوها"' in html
    assert 'rename.setAttribute("aria-label"' in script
    assert 'remove.setAttribute("aria-label"' in script
    assert ":focus-visible" in css
    assert "@media (max-width: 880px)" in css
    assert "@media (max-width: 580px)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "transition: transform 160ms ease" in css
