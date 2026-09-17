import asyncio

from fastapi import HTTPException

from apps.chatbot.errors import classify_chatbot_error


def test_llm_and_mcp_errors_are_short_operator_safe_messages():
    llm = classify_chatbot_error(HTTPException(status_code=503, detail="chatbot_llm_unavailable"))
    mcp = classify_chatbot_error(HTTPException(status_code=502, detail="chatbot_tool_failed:vm_metrics"))
    assert llm.code == "LLM_UNAVAILABLE"
    assert llm.message == "LLM پاسخ نداد. دوباره تلاش کنید."
    assert llm.retryable is True
    assert mcp.code == "MCP_TOOL_ERROR"
    assert mcp.message == "MCP پاسخ نداد. دوباره تلاش کنید."
    assert "chatbot_tool_failed" not in mcp.message


def test_timeout_and_database_errors_do_not_expose_raw_exception_text():
    timeout = classify_chatbot_error(asyncio.TimeoutError("secret upstream diagnostics"))

    class AsyncPGDatabaseError(RuntimeError):
        pass

    database = classify_chatbot_error(AsyncPGDatabaseError("postgresql://user:password@db/internal"))
    assert timeout.code == "LLM_TIMEOUT"
    assert "secret" not in timeout.message
    assert database.code == "DATABASE_ERROR"
    assert "password" not in database.message


def test_permission_and_validation_errors_are_not_retryable():
    denied = classify_chatbot_error(HTTPException(status_code=403, detail="insufficient_role"))
    invalid = classify_chatbot_error(HTTPException(status_code=400, detail="chatbot_tool_call_limit_exceeded"))
    assert denied.code == "PERMISSION_DENIED"
    assert denied.retryable is False
    assert invalid.code == "VALIDATION_ERROR"
    assert invalid.retryable is False
