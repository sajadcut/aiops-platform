from typing import Any, Dict, List, Protocol


class ZabbixClient(Protocol):
    async def get_alert(self, alert_id: str) -> Dict[str, Any]: ...


class MockZabbixClient:
    async def get_alert(self, alert_id: str) -> Dict[str, Any]:
        return {
            "id": alert_id,
            "source": "zabbix",
            "severity": "warning",
            "service": None,
            "message": "mock alert",
        }
