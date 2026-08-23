import httpx
from typing import Optional, List
from datetime import datetime, timedelta
import json
from app.integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from app.core.config import settings
from app.core.logging import logger

class ZabbixConnector(BaseConnector):
    """
    Connector برای دریافت داده از Zabbix API
    با قابلیت Fallback در صورت عدم دسترسی به Zabbix
    """
    
    def __init__(
        self,
        api_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 10
    ):
        # از settings بخوان (بعداً به config اضافه کن)
        self.api_url = api_url or getattr(settings, "ZABBIX_URL", "http://localhost:8080")
        self.username = username or getattr(settings, "ZABBIX_USERNAME", "Admin")
        self.password = password or getattr(settings, "ZABBIX_PASSWORD", "zabbix")
        self.timeout = timeout
        self._token: Optional[str] = None
        self._last_auth: Optional[datetime] = None
    
    @property
    def source_name(self) -> str:
        return "zabbix"
    
    async def health_check(self) -> bool:
        """بررسی در دسترس بودن Zabbix API"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.api_url}/api_jsonrpc.php",
                    json={
                        "jsonrpc": "2.0",
                        "method": "apiinfo.version",
                        "params": [],
                        "id": 1
                    }
                )
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Zabbix health check failed: {str(e)}")
            return False
    
    async def _authenticate(self) -> str:
        """دریافت Token از Zabbix API"""
        if self._token and self._last_auth and (datetime.now() - self._last_auth) < timedelta(minutes=10):
            return self._token
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.api_url}/api_jsonrpc.php",
                json={
                    "jsonrpc": "2.0",
                    "method": "user.login",
                    "params": {
                        "username": self.username,
                        "password": self.password
                    },
                    "id": 1
                }
            )
            data = response.json()
            if "result" in data:
                self._token = data["result"]
                self._last_auth = datetime.now()
                logger.info("Zabbix authentication successful")
                return self._token
            else:
                raise Exception(f"Zabbix authentication failed: {data}")
    
    async def _request(self, method: str, params: dict) -> dict:
        """ارسال درخواست به Zabbix API با احراز هویت خودکار"""
        token = await self._authenticate()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.api_url}/api_jsonrpc.php",
                json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "auth": token,
                    "id": 1
                }
            )
            data = response.json()
            if "error" in data:
                raise Exception(f"Zabbix API error: {data['error']}")
            return data
    
    async def get_alerts(
        self,
        since: Optional[datetime] = None,
        service: Optional[str] = None,
        limit: int = 100
    ) -> List[Alert]:
        """دریافت Alertهای فعال از Zabbix"""
        try:
            if not await self.health_check():
                logger.warning("Zabbix not available, returning empty alerts")
                return []
            
            # دریافت مشکلات فعال از Zabbix
            params = {
                "output": ["eventid", "clock", "severity", "name", "message"],
                "sortfield": "clock",
                "sortorder": "DESC",
                "limit": limit
            }
            
            # فیلتر بر اساس سرویس (در Zabbix از Hosts استفاده می‌شود)
            if service:
                params["hostids"] = await self._get_host_id(service)
            
            if since:
                params["time_from"] = int(since.timestamp())
            
            data = await self._request("problem.get", params)
            
            alerts = []
            for problem in data.get("result", []):
                # تبدیل severity عددی به متن
                severity_map = {0: "not_classified", 1: "information", 2: "warning", 
                               3: "average", 4: "high", 5: "disaster"}
                severity_num = int(problem.get("severity", 0))
                
                alerts.append(Alert(
                    source="zabbix",
                    source_id=str(problem.get("eventid", "")),
                    severity=severity_map.get(severity_num, "unknown"),
                    service=service,
                    message=problem.get("name", problem.get("message", "No message")),
                    timestamp=datetime.fromtimestamp(int(problem.get("clock", 0))),
                    raw_data=problem
                ))
            
            logger.info(f"Retrieved {len(alerts)} alerts from Zabbix")
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to get Zabbix alerts: {str(e)}")
            return []  # Fallback: لیست خالی برگردان
    
    async def _get_host_id(self, service: str) -> str:
        """دریافت Host ID بر اساس نام سرویس"""
        data = await self._request(
            "host.get",
            {
                "output": ["hostid"],
                "filter": {"host": service}
            }
        )
        hosts = data.get("result", [])
        if hosts:
            return hosts[0]["hostid"]
        return ""
    
    async def get_logs(self, service: str, since: datetime, until: Optional[datetime] = None, level: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
        """Zabbix لاگ ندارد، خالی برمی‌گرداند"""
        logger.warning("Zabbix does not support log retrieval")
        return []
    
    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        """Zabbix متریک‌های ساده دارد (در MVP فعلاً خالی)"""
        logger.warning("Zabbix metric retrieval not fully implemented in MVP")
        return []