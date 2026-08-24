import httpx
from typing import Optional, List
from datetime import datetime, timedelta
from integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from domain.contracts.config import settings
from domain.contracts.logging import logger


class ZabbixConnector(BaseConnector):
    """Connector for Zabbix API; runtime configuration comes only from Settings."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
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
                response = await client.post(
                    self._api_endpoint,
                    json={"jsonrpc": "2.0", "method": "apiinfo.version", "params": [], "id": 1},
                )
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
            response = await client.post(
                self._api_endpoint,
                json={
                    "jsonrpc": "2.0",
                    "method": "user.login",
                    "params": {"username": self.username, "password": self.password},
                    "id": 1,
                },
            )
            data = response.json()
            if "result" not in data:
                raise RuntimeError("Zabbix authentication failed")
            self._token = data["result"]
            self._last_auth = datetime.now()
            return self._token

    async def _request(self, method: str, params: dict) -> dict:
        token = await self._authenticate()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self._api_endpoint,
                json={"jsonrpc": "2.0", "method": method, "params": params, "auth": token, "id": 1},
            )
            data = response.json()
            if "error" in data:
                raise RuntimeError(f"Zabbix API error: {data['error']}")
            return data

    async def get_alerts(
        self,
        since: Optional[datetime] = None,
        service: Optional[str] = None,
        limit: int = 100,
    ) -> List[Alert]:
        try:
            if not await self.health_check():
                return []
            params = {
                "output": ["eventid", "clock", "severity", "name", "message"],
                "sortfield": "clock",
                "sortorder": "DESC",
                "limit": limit,
            }
            if service:
                params["hostids"] = await self._get_host_id(service)
            if since:
                params["time_from"] = int(since.timestamp())

            data = await self._request("problem.get", params)
            severity_map = {0: "not_classified", 1: "information", 2: "warning", 3: "average", 4: "high", 5: "disaster"}
            return [
                Alert(
                    source="zabbix",
                    source_id=str(problem.get("eventid", "")),
                    severity=severity_map.get(int(problem.get("severity", 0)), "unknown"),
                    service=service,
                    message=problem.get("name", problem.get("message", "No message")),
                    timestamp=datetime.fromtimestamp(int(problem.get("clock", 0))),
                    raw_data=problem,
                )
                for problem in data.get("result", [])
            ]
        except Exception as exc:
            logger.error(f"Failed to get Zabbix alerts: {exc}")
            return []

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
