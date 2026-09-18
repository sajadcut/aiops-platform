from pathlib import Path


def _script() -> str:
    return Path("dashboards/chatbot.js").read_text(encoding="utf-8")


def _html() -> str:
    return Path("dashboards/chatbot.html").read_text(encoding="utf-8")


def _css() -> str:
    return Path("dashboards/chatbot.css").read_text(encoding="utf-8")


def _frontend() -> str:
    return _script() + "\n" + _html()


def test_chatbot_ui_uses_session_storage_not_persistent_local_storage():
    source = _frontend()
    assert "sessionStorage" in source
    assert "localStorage" not in source
    assert '"X-API-Key"' in source
    assert "sessionStorage.removeItem(KEY_STORAGE)" in source


def test_chatbot_ui_renders_untrusted_text_without_unsafe_html_injection():
    source = _frontend()
    assert "textContent" in source
    assert "document.createTextNode" in source
    assert "innerHTML" not in source
    assert "insertAdjacentHTML" not in source


def test_chatbot_api_key_is_not_placed_in_message_payload():
    script = _script()
    assert "const payload = {message};" in script
    assert "JSON.stringify({confirm: value})" in script
    assert "api_key" not in script.lower()


def test_chatbot_product_identity_and_v3_assets_are_visible():
    html = _html()
    assert html.count("NeoBanking Operation Platform") >= 3
    assert "NEOBANKING OPERATION PLATFORM" in html
    assert "<title>NeoBanking Operation Platform</title>" in html
    assert "chatbot.css?v=7" in html
    assert "chatbot.js?v=7" in html


def test_chatbot_sidebar_has_collapse_grouping_pin_menu_and_history_controls():
    html = _html()
    source = _frontend()
    for element_id in ["sidebarCollapse", "sessionList", "sessionSearch", "newChat", "renameDialog", "deleteDialog"]:
        assert f'id="{element_id}"' in html
    assert "groupDate(" in source
    assert "Pinned" in source
    assert "Pin / Unpin" in source
    assert "session-menu-v3" in source
    assert "session-more-v3" in source
    assert "ArrowDown" in source and "ArrowUp" in source
    assert 'method: "PATCH"' in source
    assert 'method: "DELETE"' in source


def test_chatbot_empty_state_has_prompt_only_quick_operations():
    source = _frontend()
    assert "What can I help you operate?" in source
    for label in [
        "Check VM CPU",
        "Check memory usage",
        "List Kubernetes pods",
        "Inspect pod health",
        "View recent incidents",
        "Check service status",
        "Restart service",
        "Analyze an alert",
    ]:
        assert label in source
    assert "Quick actions فقط prompt را آماده می‌کنند" in source
    assert "Action Proposal" in source
    assert "prompt(value)" in source


def test_chatbot_slash_commands_only_prepare_prompts_and_keep_governance():
    html = _html()
    source = _frontend()
    assert 'id="slashMenu"' in html
    assert 'id="slashButton"' in html
    for command in ["/vm", "/k8s", "/pods", "/service", "/health", "/incident", "/help"]:
        assert command in source
    assert "Slash commands · governance unchanged" in source
    assert "prompt(item[2])" in source


def test_chatbot_command_palette_supports_keyboard_and_workspace_actions():
    html = _html()
    source = _frontend()
    assert 'id="commandPaletteDialog"' in html
    assert 'id="commandPaletteInput"' in html
    assert "New chat" in source
    assert "Search chats" in source
    assert "Toggle theme" in source
    assert "Toggle sidebar" in source
    assert "Clear conversation view" in source
    assert "Focus composer" in source
    assert "event.key.toLowerCase()" in source and '"k"' in source


def test_chatbot_context_panel_only_surfaces_real_available_context():
    html = _html()
    source = _frontend()
    assert 'id="contextPanel"' in html
    assert 'id="contextFacts"' in html
    assert 'id="activityList"' in html
    assert "Identity" in source and "Session" in source and "Conversation" in source
    assert "Context واقعی هنوز از backend دریافت نشده است." in source
    assert "MCP Ready" not in html
    assert ">Production<" not in html


def test_chatbot_api_connection_status_is_not_shown_until_authenticated_identity_exists():
    html = _html()
    source = _frontend()
    assert 'id="apiStatus" class="status-chip hidden"' in html
    assert '$("apiStatus")?.classList.remove("hidden")' in source
    assert '$("identity")?.textContent' in source


def test_chatbot_ui_preserves_persian_and_mixed_rtl_ltr_content():
    html = _html()
    script = _script()
    css = _css()
    assert '<html lang="fa" dir="rtl">' in html
    assert "CPU سرور 10.100.6.199 چقدره؟" in html
    assert 'dir="auto"' in html
    assert 'body.setAttribute("dir", "auto")' in script
    assert "unicode-bidi:plaintext" in css or "unicode-bidi: plaintext" in css
    assert 'code.setAttribute("dir", "ltr")' in script


def test_chatbot_safe_markdown_keeps_dom_only_headings_code_tables_lists_and_copy():
    script = _script()
    assert "function renderSafeMarkdown" in script
    assert "function appendInline" in script
    assert 'document.createElement("code")' in script
    assert 'document.createElement("table")' in script
    assert 'document.createElement(numbered ? "ol" : "ul")' in script
    assert "const heading = line.match" in script
    assert "copyText(" in script and "copy-code" in script
    assert "innerHTML" not in script


def test_chatbot_safe_links_are_http_only_and_open_with_no_opener():
    html = _html()
    assert "function safeLinks" in html
    assert r"/https?:\/\/[^\s<>()]+/" in html
    assert 'a.target="_blank"' in html or 'a.target = "_blank"' in html
    assert 'a.rel="noopener noreferrer"' in html or 'a.rel = "noopener noreferrer"' in html
    assert 'closest("code, pre, a")' in html


def test_chatbot_stream_transport_stop_timeout_and_terminal_outcome_are_preserved():
    script = _script()
    assert "/api/v1/chatbot/message/stream" in script
    assert "text/event-stream" in script
    assert "AbortController" in script
    assert "stopGeneration" in script
    assert "STREAM_TIMEOUT_MS" in script
    assert "stream_ended_without_terminal_event" in script
    assert "renderTerminalError" in script
    assert 'dom.sendButton.setAttribute("aria-label", active ? "توقف پاسخ" : "ارسال پیام")' in script


def test_chatbot_message_toolbar_adds_edit_regenerate_details_and_collapse():
    source = _frontend()
    assert '"message-action ui-edit"' in source
    assert '"Regenerate"' in source
    assert '"message-action ui-details"' in source
    assert "message-collapsed" in source
    assert "prompt(retryText)" in source
    assert '$("chatForm")?.requestSubmit()' in source


def test_chatbot_tool_results_keep_real_operational_facts_raw_details_and_activity_timeline():
    source = _frontend()
    css = _css()
    assert "addOperationalFacts" in source
    assert "operationalEntries" in source
    assert "tool-details" in source
    assert "tool-timeline" in source
    assert "statusText" in source and "statusMeta" in source
    assert ".operational-facts" in css
    assert ".tool-timeline" in css


def test_chatbot_action_proposals_remain_backend_governed():
    script = _script()
    css = _css()
    assert "proposal.proposal_id" in script
    assert "proposal.risk_level" in script
    assert "JSON.stringify({confirm: value})" in script
    assert "/decision" in script
    assert "تأیید و اجرا" in script or "Approve & Execute" in script
    assert ".risk-high" in css
    assert ".risk-critical" in css


def test_chatbot_error_ux_adds_a_clear_title_but_keeps_backend_message_and_retry():
    source = _frontend()
    css = _css()
    assert "Unable to complete the request" in source
    assert "renderTerminalError" in source
    assert "friendlyHttpError" in source
    assert "تلاش مجدد" in source
    assert ".error-title" in css
    assert ".error-message" in css


def test_chatbot_composer_is_autogrowing_sticky_and_has_stop_state():
    html = _html()
    script = _script()
    css = _css()
    assert 'id="messageInput"' in html
    assert "Shift+Enter" in html
    assert "Operations can require approval before execution." in html
    assert "updateComposerMetrics" in script
    assert "Math.min(dom.messageInput.scrollHeight" in script
    assert "stop-mode" in script
    assert ".composer-zone" in css
    assert ".composer:focus-within" in css


def test_chatbot_smart_scroll_does_not_force_operator_to_bottom():
    script = _script()
    html = _html()
    assert "isNearBottom" in script
    assert "updateScrollAffordance" in script
    assert 'dom.messages.addEventListener("scroll", updateScrollAffordance' in script
    assert 'id="scrollToBottom"' in html
    assert "scrollToLatest(force = false)" in script


def test_chatbot_toasts_cover_modern_workspace_interactions():
    source = _frontend()
    assert "Conversation pinned" in source
    assert "Conversation unpinned" in source
    assert "Conversation view cleared" in source
    assert "عنوان ذخیره شد" in source or "Conversation renamed" in source
    assert "گفت‌وگو حذف شد" in source or "Conversation deleted" in source
    assert "کپی شد" in source or "Copied" in source


def test_chatbot_theme_is_session_scoped_and_neutral_in_dark_and_light_modes():
    source = _frontend()
    css = _css()
    assert "THEME_STORAGE" in source
    assert "sessionStorage.setItem(THEME_STORAGE, theme)" in source
    assert "localStorage" not in source
    assert "--bg-app:#0b0d10;" in css
    assert ':root[data-theme="light"]' in css
    assert "--bg-app:#f6f7f9;" in css
    assert "--bg-surface:#ffffff;" in css
    assert "linear-gradient" not in css.lower()
    assert "transition: all" not in css.lower()


def test_chatbot_responsive_layout_has_context_drawer_sidebar_drawer_and_mobile_rules():
    css = _css()
    assert "1180px" in css
    assert "880px" in css
    assert "580px" in css
    assert ".context-panel" in css
    assert ".workspace.sidebar-collapsed" in css
    assert ".workspace.context-open" in css
    assert ".drawer-backdrop" in css


def test_chatbot_accessibility_contracts_include_live_regions_focus_and_reduced_motion():
    html = _html()
    css = _css()
    assert 'aria-controls="sidebar"' in html
    assert 'aria-controls="contextPanel"' in html
    assert 'aria-live="polite"' in html
    assert 'role="listbox"' in html
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert "::backdrop" in css


def test_chatbot_css_avoids_dashboard_style_overdecoration_and_uses_open_assistant_layout():
    css = _css()
    assert "linear-gradient" not in css.lower()
    assert "transition: all" not in css.lower()
    assert ".message.assistant .message-card" in css
    assert ".message.user .message-card" in css
    assert ".messages-inner" in css
    assert "width:min(920px,100%)" in css


def test_chatbot_branding_uses_neobanking_operation_platform_everywhere_visible():
    source = _frontend()
    assert "NeoBanking Operation Platform" in source
    assert "NeoBanking Chatbot Operation Platform" not in source
    assert "Enterprise Operations Copilot" not in source
    assert "Operations Copilot" not in source
