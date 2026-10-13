"""Elastic ES|QL requests/responses must never be logged as raw records."""
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
from integrations.mcp_client import MCPClient


def test_esql_mcp_query_is_not_in_application_log_payload():
    client = ElasticsearchMCPClient()
    try:
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "platform_core_execute_esql",
            "arguments": {"query": 'FROM logs-* WHERE message == "PRIVATE_QUERY_TEXT"'},
        }}
        safe = client._safe_mcp_log(request, method="tools/call", tool_name=client.TOOL_EXECUTE_ESQL)
        assert safe["omitted"] == "elastic_esql_payload"
        assert "PRIVATE_QUERY_TEXT" not in str(safe)
        assert "query" not in str(safe)
    finally:
        import asyncio
        asyncio.run(client.close())


def test_esql_mcp_result_and_tool_errors_are_not_in_application_log_payload():
    client = ElasticsearchMCPClient()
    try:
        for value in (
            {"result": {"content": [{"type": "text", "text": "PRIVATE_LOG_PAYLOAD"}]}},
            {"result": {"isError": True, "content": [{"type": "text", "text": "PRIVATE_ERROR_PAYLOAD"}]}},
            {"isError": True, "content": [{"type": "text", "text": "PRIVATE_ERROR_PAYLOAD"}]},
        ):
            safe = client._safe_mcp_log(value, method="tools/call", tool_name=client.TOOL_EXECUTE_ESQL)
            assert safe["omitted"] == "elastic_esql_payload"
            assert "PRIVATE_" not in str(safe)
    finally:
        import asyncio
        asyncio.run(client.close())


def test_non_elastic_mcp_logging_contract_unchanged():
    assert MCPClient._bounded_for_log({"status": "ok"}) == {"status": "ok"}
