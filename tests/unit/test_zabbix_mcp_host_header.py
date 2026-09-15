import asyncio

from domain.contracts.config import settings
from integrations.zabbix.mcp_client import ZabbixMCPClient


def test_zabbix_mcp_client_applies_configured_host_header(monkeypatch):
    monkeypatch.setattr(settings, "ZABBIX_MCP_HOST_HEADER", "localhost:5080")
    client = ZabbixMCPClient("http://10.100.8.38:5080/mcp")
    try:
        assert client._client.headers["Host"] == "localhost:5080"
    finally:
        asyncio.run(client.close())
