from pathlib import Path


def _script() -> str:
    return Path("dashboards/chatbot.js").read_text(encoding="utf-8")


def _ui() -> str:
    return Path("dashboards/chatbot-ui.js").read_text(encoding="utf-8")


def _transport() -> str:
    return Path("dashboards/chatbot-transport.js").read_text(encoding="utf-8")


def _html() -> str:
    return Path("dashboards/chatbot.html").read_text(encoding="utf-8")


def _css() -> str:
    return Path("dashboards/chatbot.css").read_text(encoding="utf-8")


def _main() -> str:
    return Path("apps/api/main.py").read_text(encoding="utf-8")


def _frontend() -> str:
    return "\n".join((_script(), _ui(), _transport(), _html()))


def test_chatbot_api_key_remains_session_only_while_ui_preferences_may_persist():
    source = _frontend()
    script = _script()
    ui = _ui()
    assert "sessionStorage.setItem(KEY_STORAGE" in script
    assert "sessionStorage.removeItem(KEY_STORAGE)" in script
    assert "localStorage.setItem(KEY_STORAGE" not in source
    assert "localStorage.getItem(KEY_STORAGE" not in source
    assert '"X-API-Key"' in _transport()
    assert "localStorage.setItem(THEME_STORAGE" in ui
    assert "localStorage.setItem(SIDEBAR_STORAGE" in script


def test_chatbot_untrusted_content_uses_safe_dom_rendering_without_html_injection():
    source = _frontend()
    assert "textContent" in source
    assert "document.createTextNode" in source
    assert "innerHTML" not in source
    assert "insertAdjacentHTML" not in source
    assert "eval(" not in source


def test_chatbot_api_key_is_not_placed_in_message_or_decision_payloads():
    script = _script()
    assert "const payload = {message};" in script
    assert "JSON.stringify({confirm: value})" in script
    assert "api_key" not in script.lower()


def test_chatbot_product_identity_is_exact_and_prominent():
    html = _html()
    script = _script()
    title = "NeoBanking Chatbot Operation Platform"
    assert html.count(title) >= 3
    assert f"<title>{title}</title>" in html
    assert f'<div class="product-title">{title}</div>' in html
    assert title in script
    assert "AI-Powered Operations Copilot" in html
    assert '"Operations Copilot"' in script


def test_chatbot_empty_state_has_non_clickable_capability_badges_not_hardcoded_quick_actions():
    script = _script()
    html = _html()
    for label in ["VM", "Kubernetes", "Zabbix", "Logs", "Service Health"]:
        assert f'"{label}"' in script
    assert "capability-chip" in script
    assert "quick-actions" not in html
    assert "quick-action" not in script
    assert "Check VM CPU" not in _frontend()
    assert "Restart service" not in _frontend()
    assert "data-prompt" not in _frontend()
    assert "10.100.6.199" not in html


def test_chatbot_theme_has_independent_dark_and_neutral_light_palettes():
    css = _css()
    assert "--bg-primary: #0B0F14;" in css
    assert "--bg-secondary: #0F141B;" in css
    assert "--surface-primary: #151B23;" in css
    assert "--border-primary: #253040;" in css
    assert "--text-primary: #E6EDF3;" in css
    assert "--accent-primary: #5B8DEF;" in css
    assert ':root[data-theme="light"]' in css
    assert "--bg-primary: #F6F8FA;" in css
    assert "--surface-primary: #FFFFFF;" in css
    assert "--border-primary: #DDE3EA;" in css
    assert "--text-primary: #17202A;" in css
    assert "--text-secondary: #58636F;" in css
    assert "--user-surface: #EEF1F4;" in css
    assert "linear-gradient" not in css.lower()
    assert "transition: all" not in css.lower()


def test_chatbot_theme_toggle_is_labeled_persistent_and_respects_system_preference():
    html = _html()
    ui = _ui()
    script = _script()
    assert 'id="themeToggle"' in html
    assert 'id="themeMoon"' in html
    assert 'id="themeSun"' in html
    assert 'id="themeLabel"' in html
    assert "prefers-color-scheme: light" in ui
    assert "localStorage.getItem(THEME_STORAGE)" in ui
    assert "localStorage.setItem(THEME_STORAGE" in ui
    assert "setTheme(initialTheme())" in script
    assert "sessionStorage.setItem(THEME_STORAGE" not in _frontend()


def test_chatbot_login_supports_show_hide_without_changing_secret_boundary():
    html = _html()
    script = _script()
    assert 'id="apiKeyToggle"' in html
    assert 'type="password"' in html
    assert "toggleApiKeyVisibility" in script
    assert 'dom.apiKeyInput.type = visible ? "password" : "text"' in script
    assert "sessionStorage.setItem(KEY_STORAGE" in script


def test_chatbot_frontend_is_split_into_transport_ui_and_app_modules():
    html = _html()
    script = _script()
    main = _main()
    assert 'type="module"' in html
    assert "chatbot.js?v=8" in html
    assert 'from "./chatbot-ui.js?v=8"' in script
    assert 'from "./chatbot-transport.js?v=8"' in script
    assert '"/chatbot/chatbot-ui.js"' in main
    assert '"/chatbot/chatbot-transport.js"' in main
    assert "createTransport" in _transport()


def test_chatbot_safe_markdown_supports_required_blocks_and_ltr_code():
    ui = _ui()
    assert "function appendInline" in ui
    assert "export function renderSafeMarkdown" in ui
    assert 'document.createElement("strong")' in ui
    assert 'document.createElement("code")' in ui
    assert 'document.createElement("table")' in ui
    assert 'document.createElement(numbered ? "ol" : "ul")' in ui
    assert 'document.createElement("blockquote")' in ui
    assert "headingLevel" in ui
    assert 'code.setAttribute("dir", "ltr")' in ui
    assert "copy-code" in ui
    assert "innerHTML" not in ui


def test_chatbot_preserves_persian_english_mixed_bidi_and_code_direction():
    html = _html()
    script = _script()
    ui = _ui()
    css = _css()
    assert '<html lang="fa" dir="rtl">' in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert "فارسی" in html
    assert "English" in html
    assert "unicode-bidi: plaintext" in css
    assert 'code.setAttribute("dir", "ltr")' in ui


def test_chatbot_stream_transport_has_terminal_contract_stop_timeout_and_no_silent_request():
    script = _script()
    transport = _transport()
    html = _html()
    assert "/api/v1/chatbot/message/stream" in transport
    assert "text/event-stream" in transport
    assert "stream_ended_without_terminal_event" in transport
    assert "AbortController" in script
    assert "stopGeneration" in script
    assert "STREAM_TIMEOUT_MS" in script
    assert 'stopGeneration("timeout")' in script
    assert "INCOMPLETE_STREAM" in script
    assert "پاسخ متوقف شد." in script
    assert 'class="stop-icon ui-icon hidden"' in html


def test_chatbot_streaming_has_typing_cursor_status_and_smart_scroll():
    script = _script()
    css = _css()
    html = _html()
    assert "typing-cursor" in script
    assert "cursor-blink" in css
    assert "در حال تحلیل درخواست…" in script
    assert "در حال نوشتن پاسخ…" in script
    assert "isNearBottom" in script
    assert "updateScrollAffordance" in script
    assert 'dom.messages.addEventListener("scroll", updateScrollAffordance' in script
    assert 'id="scrollToBottom"' in html


def test_chatbot_composer_autogrows_and_disables_empty_send():
    html = _html()
    script = _script()
    assert 'id="messageInput"' in html
    assert "درباره وضعیت زیرساخت یا سرویس‌ها سؤال کنید" in html
    assert "Shift+Enter" in html
    assert 'id="sendButton"' in html and "disabled" in html
    assert "Math.min(dom.messageInput.scrollHeight, 190)" in script
    assert "dom.sendButton.disabled = state.activeController ? false : !dom.messageInput.value.trim()" in script


def test_chatbot_history_has_search_active_state_rename_delete_new_chat_and_skeleton_loading():
    html = _html()
    script = _script()
    css = _css()
    for element_id in ["sessionList", "sessionSearch", "newChat", "renameDialog", "deleteDialog"]:
        assert f'id="{element_id}"' in html
    assert "renderSessionSkeleton" in script
    assert 'method: "PATCH"' in script
    assert 'method: "DELETE"' in script
    assert "session-row.active" in css
    assert "formatSessionTime" in script


def test_chatbot_sidebar_supports_desktop_collapse_and_mobile_drawer():
    html = _html()
    script = _script()
    css = _css()
    assert 'id="sidebarCollapse"' in html
    assert "setSidebarCollapsed" in script
    assert "SIDEBAR_STORAGE" in script
    assert ".workspace.sidebar-collapsed" in css
    assert ".sidebar.open" in css
    assert "@media (max-width: 880px)" in css
    assert 'aria-controls="sidebar"' in html


def test_chatbot_tool_results_use_compact_operational_facts_and_raw_details_only_on_demand():
    script = _script()
    ui = _ui()
    css = _css()
    assert "addOperationalFacts" in script
    assert "addDetails" in script
    for metric in ["CPU", "Memory", "Disk", "Load"]:
        assert f'["{metric}"' in ui
    assert "tool-details" in ui
    assert ".operational-facts" in css
    assert "JSON.stringify(data, null, 2)" in ui


def test_chatbot_action_proposals_stay_backend_governed_and_show_risk_source_when_available():
    script = _script()
    css = _css()
    assert "proposal.proposal_id" in script
    assert "proposal.risk_level" in script
    assert '["Source", proposal.source || proposal.tool]' in script
    assert "JSON.stringify({confirm: value})" in script
    assert "/decision" in script
    assert "تأیید و اجرا" in script
    assert "رد کردن" in script
    assert ".risk-high" in css
    assert ".risk-critical" in css


def test_chatbot_error_ui_is_compact_retryable_and_never_renders_raw_exception_text():
    script = _script()
    ui = _ui()
    css = _css()
    assert "renderTerminalError" in script
    assert "friendlyHttpError" in script
    assert "تلاش مجدد" in script
    assert "addErrorMeta" in script
    assert "Request" in ui and "Component" in ui and "Code" in ui and "Timestamp" in ui
    assert ".error-meta" in css
    assert "traceback" not in _frontend().lower()


def test_chatbot_dialogs_have_accessible_labels_focus_targets_and_requested_delete_copy():
    html = _html()
    script = _script()
    css = _css()
    assert 'aria-labelledby="renameTitle"' in html
    assert 'aria-labelledby="deleteTitle"' in html
    assert "autofocus" in html
    assert "این گفتگو حذف شود؟" in html
    assert "این کار تاریخچه گفتگو را از رابط کاربری حذف می‌کند." in html
    assert "حذف گفتگو" in html
    assert "dom.renameInput.focus()" in script
    assert "dom.deleteCancel.focus()" in script
    assert ".modal::backdrop" in css


def test_chatbot_accessibility_and_responsive_contracts_are_present():
    html = _html()
    script = _script()
    css = _css()
    assert 'aria-live="polite"' in html
    assert 'aria-busy="false"' in html
    assert 'aria-expanded="true"' in html
    assert 'aria-label="جست‌وجوی گفت‌وگوها"' in html
    assert ":focus-visible" in css
    assert "@media (max-width: 880px)" in css
    assert "@media (max-width: 580px)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "dom.messages.setAttribute(\"aria-busy\"" in script


def test_chatbot_layout_uses_bounded_conversation_width_and_tokenized_spacing_radius():
    css = _css()
    assert "--content-width: 980px;" in css
    assert "--sidebar-width: 284px;" in css
    for token in ["--space-1: 4px;", "--space-2: 8px;", "--space-3: 12px;", "--space-4: 16px;", "--space-6: 24px;", "--space-8: 32px;"]:
        assert token in css
    for token in ["--radius-sm: 8px;", "--radius-md: 12px;", "--radius-lg: 16px;"]:
        assert token in css
