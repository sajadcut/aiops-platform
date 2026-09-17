from pathlib import Path


def test_chatbot_ui_uses_session_storage_not_persistent_local_storage():
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")
    assert "sessionStorage" in script
    assert "localStorage" not in script
    assert '"X-API-Key"' in script
    assert "sessionStorage.removeItem(KEY_STORAGE)" in script


def test_chatbot_ui_renders_server_text_without_inner_html():
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script


def test_chatbot_api_key_is_not_placed_in_message_payload():
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")
    # The key is confined to the authentication header helper. Chat bodies only
    # contain the user's message/session or an explicit boolean decision.
    assert 'const payload = {message};' in script
    assert 'JSON.stringify({confirm: value})' in script
    assert "api_key" not in script.lower()
