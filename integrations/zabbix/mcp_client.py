from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from domain.contracts.config import settings
from domain.contracts.logging import logger
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
            authorization_header=settings.ZABBIX_MCP_AUTH_HEADER,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
        )
        host_header = str(settings.ZABBIX_MCP_HOST_HEADER or "").strip()
        if host_header:
            self._client.headers["Host"] = host_header

    @staticmethod
    def _dt(value: object) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        text = str(value).strip()
        if text.isdigit():
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d %H:%M UTC", "%Y-%m-%d %H:%M:%S UTC"):
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return datetime.now(timezone.utc)

    @staticmethod
    def _severity(value: object) -> str:
        mapping = {"0": "not_classified", "1": "information", "2": "warning", "3": "average", "4": "high", "5": "disaster"}
        return mapping.get(str(value), str(value or "unknown").lower())

    @staticmethod
    def _tool_error_text(result: dict[str, Any]) -> str:
        for part in result.get("content", []) or []:
            if isinstance(part, dict) and part.get("type") == "text" and part.get("text"):
                return str(part["text"]).strip()
        return "unknown MCP tool error"

    async def _active_problem_fallback(self) -> dict[str, Any]:
        args: dict[str, Any] = {}
        if settings.ZABBIX_MCP_SERVER_NAME:
            args["server"] = settings.ZABBIX_MCP_SERVER_NAME
        result = await self.call_tool("problem_active_get", args)
        if result.get("isError") is True:
            detail = self._tool_error_text(result)
            raise RuntimeError(f"zabbix_mcp_tool_error:problem_active_get:{detail}")
        return result

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        args: dict[str, Any] = {
            "output": "extend", "recent": True, "sortfield": "eventid", "sortorder": "DESC",
            "limit": min(max(int(limit), 1), 500),
        }
        if since:
            args["time_from"] = int(since.timestamp())
        if service:
            args["search"] = {"name": service}
            args["searchByAny"] = True
        if settings.ZABBIX_MCP_SERVER_NAME:
            args["server"] = settings.ZABBIX_MCP_SERVER_NAME

        fallback_used = False
        try:
            result = await self.call_tool("problem_get", args)
            if result.get("isError") is True:
                logger.warning("zabbix_problem_get_failed_using_active_fallback", detail=self._tool_error_text(result))
                result = await self._active_problem_fallback()
                fallback_used = True
        except Exception as exc:
            logger.warning("zabbix_problem_get_exception_using_active_fallback", error_type=type(exc).__name__)
            result = await self._active_problem_fallback()
            fallback_used = True

        alerts: List[Alert] = []
        wanted_service = str(service or "").strip().lower()
        for payload in self.json_content(result):
            if isinstance(payload, dict) and isinstance(payload.get("problems"), list):
                candidates = payload["problems"]
            else:
                candidates = payload if isinstance(payload, list) else [payload]
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                timestamp = self._dt(item.get("clock") or item.get("timestamp") or item.get("time"))
                if since and timestamp < since:
                    continue
                message = str(item.get("name") or item.get("message") or "Zabbix problem")
                host = str(item.get("host") or "")
                if fallback_used and wanted_service and wanted_service not in f"{message} {host}".lower():
                    continue
                alerts.append(Alert(
                    source="zabbix",
                    source_id=str(item.get("eventid") or item.get("problemid") or item.get("objectid") or ""),
                    severity=self._severity(item.get("severity")),
                    service=str(item.get("service") or service or host or "unknown"),
                    message=message, timestamp=timestamp, raw_data=item,
                ))
        return alerts[: min(max(int(limit), 1), 500)]
