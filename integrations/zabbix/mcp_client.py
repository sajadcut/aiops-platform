from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from domain.contracts.config import settings
from integrations.base import Alert
from integrations.mcp_client import MCPClient


class ZabbixMCPClient(MCPClient):
    """Read-only adapter for initMAX/zabbix-mcp-server monitoring tools."""

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(
            server_url or settings.ZABBIX_MCP_URL,
            "zabbix",
            allowed_tools={"problem_get", "problem_active_get", "event_get", "host_get", "host_status_get", "health_check"},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )

    @staticmethod
    def _dt(value: object) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        text = str(value)
        if text.isdigit():
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    @staticmethod
    def _severity(value: object) -> str:
        mapping = {"0": "not_classified", "1": "information", "2": "warning", "3": "average", "4": "high", "5": "disaster"}
        return mapping.get(str(value), str(value or "unknown").lower())

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        args: dict[str, Any] = {
            "output": "extend",
            "recent": True,
            "sortfield": "eventid",
            "sortorder": "DESC",
            "limit": min(max(int(limit), 1), 500),
        }
        if since:
            args["time_from"] = int(since.timestamp())
        if service:
            args["search"] = {"name": service}
            args["searchByAny"] = True
        server_name = settings.ZABBIX_MCP_SERVER_NAME
        if server_name:
            args["server"] = server_name

        # problem_get is part of the core Monitoring API surface and therefore
        # safer for deterministic Evidence collection than broad/raw API tools.
        result = await self.call_tool("problem_get", args)
        alerts: List[Alert] = []
        for payload in self.json_content(result):
            candidates = payload if isinstance(payload, list) else [payload]
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                timestamp = self._dt(item.get("clock") or item.get("timestamp"))
                if since and timestamp < since:
                    continue
                message = str(item.get("name") or item.get("message") or "Zabbix problem")
                alerts.append(Alert(
                    source="zabbix",
                    source_id=str(item.get("eventid") or item.get("problemid") or item.get("objectid") or ""),
                    severity=self._severity(item.get("severity")),
                    service=str(item.get("service") or service or "unknown"),
                    message=message,
                    timestamp=timestamp,
                    raw_data=item,
                ))
        return alerts[: min(max(int(limit), 1), 500)]
