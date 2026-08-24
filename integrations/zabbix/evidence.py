from __future__ import annotations
from typing import Any, Dict, Iterable, List

class ZabbixEvidenceAdapter:
    @staticmethod
    def normalize(alerts: Iterable[Any]) -> List[Dict[str, Any]]:
        result = []
        for alert in alerts:
            raw = getattr(alert, "raw_data", {}) or {}
            source_id = getattr(alert, "source_id", None) or raw.get("eventid") or "unknown"
            result.append({
                "id": f"zabbix:{source_id}",
                "type": "alert",
                "source": "zabbix",
                "reference": str(source_id),
                "confidence": 1.0,
                "raw_data": raw,
            })
        return result
