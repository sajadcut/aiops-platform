from pathlib import Path


def _script() -> str:
    return Path("dashboards/chatbot.js").read_text(encoding="utf-8")


def _html() -> str:
    return Path("dashboards/chatbot.html").read_text(encoding="utf-8")


def test_stop_button_bypasses_required_form_validation_and_aborts_stream():
    script = _script()
    html = _html()

    assert 'id="messageInput"' in html
    assert "required" in html
    assert 'dom.sendButton.type = active ? "button" : "submit";' in script
    assert 'dom.sendButton.addEventListener("click", (event) => {' in script
    assert 'if (!state.activeController) return;' in script
    assert 'stopGeneration("user");' in script
    assert "state.activeController.abort();" in script
    assert 'showStatus("در حال توقف پاسخ…", "cancel")' in script


def test_error_retry_control_has_exactly_one_implementation_path():
    script = _script()
    html = _html()

    # The old v3 inline enhancer was removed. Lock the stronger invariant:
    # retry is created exactly once by the modular application and never by HTML.
    assert script.count('retry.className = "retry-button ui-regenerate";') == 1
    assert "ui-regenerate" not in html


def test_typed_backend_error_component_is_visible_to_operator():
    script = _script()

    assert 'source: data && data.component ? String(data.component).toUpperCase() : ""' in script
