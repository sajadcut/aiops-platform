from pathlib import Path


def test_operator_messages_expose_copy_action_without_changing_message_text():
    script = Path("dashboards/chatbot.js").read_text(encoding="utf-8")

    assert 'if (kind !== "action_proposal")' in script
    assert 'role === "user" ? "کپی پیام شما" : "کپی پاسخ"' in script
    assert 'copyText(role === "user" ? text : (body.textContent || text))' in script
    assert 'if (role !== "user" && kind !== "action_proposal")' not in script
