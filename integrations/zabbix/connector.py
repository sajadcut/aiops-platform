import httpx
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from domain.contracts.config import settings
from domain.contracts.logging import logger


class ZabbixConnector(BaseConnector):
    """Zabbix connector with deterministic host/asset enrichment."""

    def __init__(self, api_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, timeout: Optional[int] = None):
        self.api_url = api_url or settings.ZABBIX_URL
        self.username = username if username is not None else settings.ZABBIX_USERNAME
        self.password = password if password is not None else settings.ZABBIX_PASSWORD
        self.timeout = timeout if timeout is not None else settings.ZABBIX_TIMEOUT_SECONDS
        self._token: Optional[str] = None
        self._last_auth: Optional[datetime] = None

    @property
    def source_name(self) -> str:
        return "zabbix"

    @property
    def _api_endpoint(self) -> str:
        return f"{self.api_url.rstrip('/')}/api_jsonrpc.php"

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self._api_endpoint, json={"jsonrpc": "2.0", "method": "apiinfo.version", "params": [], "id": 1})
                return response.status_code == 200
        except Exception as exc:
            logger.warning(f"Zabbix health check failed: {exc}")
            return False

    async def _authenticate(self) -> str:
        if self._token and self._last_auth and (datetime.now() - self._last_auth) < timedelta(minutes=10):
            return self._token
        if not self.username or not self.password:
            raise RuntimeError("ZABBIX_USERNAME and ZABBIX_PASSWORD must be configured")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self._api_endpoint, json={"jsonrpc": "2.0", "method": "user.login", "params": {"username": self.username, "password": self.password}, "id": 1})
            data = response.json()
            if "result" not in data:
                raise RuntimeError("Zabbix authentication failed")
            self._token = data["result"]
            self._last_auth = datetime.now()
            return self._token

    async def _request(self, method: str, params: dict) -> dict:
        token = await self._authenticate()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self._api_endpoint, json={"jsonrpc": "2.0", "method": method, "params": params, "auth": token, "id": 1})
            response.raise_for_status()
            data = response.json()
            if "error" in data:
                raise RuntimeError(f"Zabbix API error: {data['error']}")
            return data

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        try:
            if not await self.health_check():
                return []
            params: Dict[str, Any] = {"output": "extend", "selectTags": "extend", "sortfield": "clock", "sortorder": "DESC", "limit": limit}
            if service:
                host_id = await self._get_host_id(service)
                if host_id:
                    params["hostids"] = host_id
            if since:
                params["time_from"] = int(since.timestamp())
            data = await self._request("problem.get", params)
            severity_map = {0: "not_classified", 1: "information", 2: "warning", 3: "average", 4: "high", 5: "disaster"}
            alerts: List[Alert] = []
            for problem in data.get("result", []):
                raw = dict(problem)
                try:
                    raw.update(await self._asset_metadata_for_problem(problem))
                except Exception as exc:
                    logger.warning(f"Zabbix asset enrichment failed for event {problem.get('eventid')}: {exc}")
                host = raw.get("host") or {}
                resolved_service = service or host.get("host") or host.get("name")
                alerts.append(Alert(source="zabbix", source_id=str(problem.get("eventid", "")), severity=severity_map.get(int(problem.get("severity", 0)), "unknown"), service=resolved_service, message=problem.get("name", problem.get("message", "No message")), timestamp=datetime.fromtimestamp(int(problem.get("clock", 0))), raw_data=raw))
            return alerts
        except Exception as exc:
            logger.error(f"Failed to get Zabbix alerts: {exc}")
            return []

    async def _asset_metadata_for_problem(self, problem: Dict[str, Any]) -> Dict[str, Any]:
        trigger_id = str(problem.get("objectid") or "")
        if not trigger_id:
            return {}
        trigger_data = await self._request("trigger.get", {"triggerids": [trigger_id], "output": ["triggerid", "description", "priority"], "selectHosts": ["hostid", "host", "name"], "selectTags": "extend"})
        triggers = trigger_data.get("result", [])
        if not triggers:
            return {}
        trigger = triggers[0]
        hosts = trigger.get("hosts") or []
        if not hosts:
            return {"trigger": trigger}
        host_id = hosts[0].get("hostid")
        host_data = await self._request("host.get", {"hostids": [host_id], "output": ["hostid", "host", "name", "status"], "selectGroups": ["groupid", "name"], "selectParentTemplates": ["templateid", "name", "host"], "selectTags": "extend", "selectInterfaces": ["interfaceid", "ip", "dns", "type", "main", "useip"], "selectInventory": "extend"})
        enriched_hosts = host_data.get("result", [])
        host = enriched_hosts[0] if enriched_hosts else hosts[0]
        combined_tags = []
        for tag in (problem.get("tags") or []) + (trigger.get("tags") or []) + (host.get("tags") or []):
            if isinstance(tag, dict) and tag not in combined_tags:
                combined_tags.append(tag)
        return {"trigger": trigger, "host": host, "hostid": str(host_id), "tags": combined_tags, "inventory": host.get("inventory") or {}}

    async def _get_host_id(self, service: str) -> str:
        data = await self._request("host.get", {"output": ["hostid"], "filter": {"host": service}})
        hosts = data.get("result", [])
        return hosts[0]["hostid"] if hosts else ""

    async def get_logs(self, service: str, since: datetime, until: Optional[datetime] = None, level: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
        logger.warning("Zabbix does not support log retrieval")
        return []

    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        logger.warning("Zabbix metric retrieval is not enabled by this connector")
        return []
