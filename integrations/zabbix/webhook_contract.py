"""Contract for the Zabbix Team Guide v1.1 Webhook payload.

Zabbix pushes {"payload": {...}}. Its Media Type script copies recognized
EVENT.TAGSJSON values into flat fields; both the flat fields and the tag array
are accepted. No host/service/trigger text is promoted into an execution target.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Names are intentionally identical to the Media Type's JS parameter output.
IDENTITY_FIELDS = (
    "platform", "asset_type", "environment", "service", "business_service",
    "owner", "datacenter", "correlation_key", "cluster", "namespace",
    "workload_kind", "workload", "pod", "node", "target_ip", "fqdn",
    "endpoint", "database", "db_engine", "db_instance", "device", "interface",
    "filesystem",
)
_ZABBIX_MACRO = re.compile(r"^\{[^{}]+\}$")


def clean_zabbix_value(value: Any) -> str:
    """Match the Zabbix webhook script's handling of unresolved macros."""
    if value is None or isinstance(value, (list, dict)):
        return ""
    text = str(value).strip()
    if text.upper() in {"", "UNKNOWN", "*UNKNOWN*"} or _ZABBIX_MACRO.fullmatch(text):
        return ""
    return text


def zabbix_tags(value: Any) -> list[dict[str, str]]:
    """Accept the actual JS array and JSON-text legacy parameter formats."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return []
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = clean_zabbix_value(item.get("tag") or item.get("key")).lower()
        if not name:
            continue
        result.append({"tag": name, "value": clean_zabbix_value(item.get("value"))})
    return result


def normalize_zabbix_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Preserve original event fields; fill only absent identity fields from tags.

    This function never guesses target_ip from host_ip, HOST.HOST, free text or
    service and never guesses Kubernetes namespace/workload from a pod name.
    """
    normalized = dict(payload)
    tags = zabbix_tags(normalized.get("tags"))
    normalized["tags"] = tags
    tag_map = {item["tag"]: item["value"] for item in tags if item["value"]}

    for field in IDENTITY_FIELDS:
        explicit = clean_zabbix_value(normalized.get(field))
        if field == "target_port":
            continue
        value = explicit or tag_map.get(field, "")
        if value:
            normalized[field] = value
        elif field in normalized:
            normalized.pop(field)

    # The Media Type script emits target_port as an integer only when valid.
    port_text = clean_zabbix_value(normalized.get("target_port")) or tag_map.get("target_port", "")
    if re.fullmatch(r"[0-9]{1,5}", port_text or "") and 1 <= int(port_text) <= 65535:
        normalized["target_port"] = int(port_text)
    else:
        normalized.pop("target_port", None)

    # Strip unresolved macros from lifecycle identity: a literal "{EVENT.ID}"
    # must not accidentally become an idempotency key across real incidents.
    for field in (
        "eventid", "event_value", "event_status", "recovery_eventid",
        "recovery_timestamp", "timestamp", "hostid", "host_ip",
        "host_name", "triggerid", "trigger",
    ):
        if field in normalized:
            normalized[field] = clean_zabbix_value(normalized[field])

    # The event identity is required for deterministic retry deduplication.
    if not clean_zabbix_value(normalized.get("eventid")):
        raise ValueError("zabbix_eventid_required")
    return normalized


def zabbix_event_time(value: Any) -> Optional[datetime]:
    """Zabbix EVENT.TIMESTAMP may be Unix seconds; ISO-8601 is also accepted."""
    raw = clean_zabbix_value(value)
    if not raw:
        return None
    try:
        if re.fullmatch(r"[0-9]{1,13}", raw):
            epoch = int(raw)
            # Support millisecond epochs for site-specific Zabbix scripts.
            if len(raw) == 13:
                epoch /= 1000
            parsed = datetime.fromtimestamp(epoch, timezone.utc)
        else:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
