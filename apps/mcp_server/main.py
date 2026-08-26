from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from domain.contracts.config import settings
from integrations.elasticsearch.client import ElasticsearchClient
from integrations.kubernetes.client import KubernetesEvidenceClient
from integrations.prometheus.client import PrometheusClient
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.zabbix.connector import ZabbixConnector


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: Dict[str, Any] = Field(default_factory=dict)
    id: int | str | None = None


app = FastAPI(title=f"AIOps MCP Server ({settings.MCP_SERVER_PROVIDER})", docs_url=None, redoc_url=None)
_WRITE_TOOLS = {"restart_service"}

_TOOL_SCHEMAS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "zabbix": {
        "get_zabbix_alerts": {
            "description": "Read active Zabbix alerts for a service/time window",
            "inputSchema": {"type": "object", "properties": {"service": {"type": ["string", "null"]}, "since": {"type": ["string", "null"]}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}}},
        },
    },
    "elasticsearch": {
        "search_logs": {
            "description": "Read Elasticsearch logs for a service/time window",
            "inputSchema": {"type": "object", "required": ["service", "since"], "properties": {"service": {"type": "string"}, "since": {"type": "string"}, "until": {"type": ["string", "null"]}, "level": {"type": ["string", "null"]}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}}},
        },
    },
    "prometheus": {
        "query_metrics": {
            "description": "Read Prometheus metric samples for a service/time window",
            "inputSchema": {"type": "object", "required": ["service", "metric_names", "since"], "properties": {"service": {"type": "string"}, "metric_names": {"type": "array", "items": {"type": "string"}, "maxItems": 25}, "since": {"type": "string"}, "until": {"type": ["string", "null"]}}},
        },
        "get_prometheus_alerts": {
            "description": "Read Prometheus/Alertmanager alerts",
            "inputSchema": {"type": "object", "properties": {"service": {"type": ["string", "null"]}, "since": {"type": ["string", "null"]}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}}},
        },
    },
    "kubernetes": {
        "collect_kubernetes_evidence": {
            "description": "Collect read-only pod/event/log Evidence for a service",
            "inputSchema": {"type": "object", "required": ["service"], "properties": {"service": {"type": "string"}}},
        },
    },
    "vm": {
        "collect_vm_metrics": {"description": "Collect allowlisted Linux VM metrics", "inputSchema": {"type": "object", "required": ["target"], "properties": {"target": {"type": "string"}}}},
        "service_status": {"description": "Read service status", "inputSchema": {"type": "object", "required": ["target", "service"], "properties": {"target": {"type": "string"}, "service": {"type": "string"}}}},
        "process_snapshot": {"description": "Read process snapshot", "inputSchema": {"type": "object", "required": ["target"], "properties": {"target": {"type": "string"}}}},
        "restart_service": {"description": "Restart one validated service through approved Execution Service", "inputSchema": {"type": "object", "required": ["target", "service", "approval_id"], "properties": {"target": {"type": "string"}, "service": {"type": "string"}, "approval_id": {"type": "string", "minLength": 1}}}},
    },
}


def _provider() -> str:
    provider = settings.MCP_SERVER_PROVIDER.strip().lower()
    if provider not in _TOOL_SCHEMAS:
        raise RuntimeError(f"unsupported_mcp_server_provider:{provider}")
    return provider


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _limit(value: Any, default: int = 100) -> int:
    return min(max(int(value or default), 1), 500)


def _authorize(authorization: str | None, tool: str | None = None) -> None:
    if settings.APP_ENV == "production" and not settings.MCP_SERVER_REQUIRE_AUTH:
        raise HTTPException(status_code=503, detail="mcp_server_auth_required_in_production")
    if not settings.MCP_SERVER_REQUIRE_AUTH:
        return
    token = settings.MCP_WRITE_BEARER_TOKEN if tool in _WRITE_TOOLS else settings.MCP_BEARER_TOKEN
    if not token:
        detail = "mcp_write_identity_not_configured" if tool in _WRITE_TOOLS else "mcp_server_identity_not_configured"
        raise HTTPException(status_code=503, detail=detail)
    expected = f"Bearer {token}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid_mcp_identity")


async def _call(provider: str, tool: str, args: Dict[str, Any]) -> Any:
    if tool not in _TOOL_SCHEMAS[provider]:
        raise PermissionError(f"tool_not_allowed:{provider}:{tool}")

    if provider == "zabbix":
        connector = ZabbixConnector()
        items = await connector.get_alerts(since=_parse_dt(args.get("since")), service=args.get("service"), limit=_limit(args.get("limit")))
        return [item.model_dump(mode="json") for item in items]

    if provider == "elasticsearch":
        connector = ElasticsearchClient()
        service = str(args.get("service") or "").strip()
        if not service:
            raise ValueError("service_required")
        since = _parse_dt(args.get("since"))
        if since is None:
            raise ValueError("since_required")
        items = await connector.get_logs(service, since, _parse_dt(args.get("until")), args.get("level"), _limit(args.get("limit")))
        return [item.model_dump(mode="json") for item in items]

    if provider == "prometheus":
        connector = PrometheusClient()
        if tool == "get_prometheus_alerts":
            items = await connector.get_alerts(since=_parse_dt(args.get("since")), service=args.get("service"), limit=_limit(args.get("limit")))
            return [item.model_dump(mode="json") for item in items]
        service = str(args.get("service") or "").strip()
        names = [str(x) for x in list(args.get("metric_names") or [])[:25]]
        since = _parse_dt(args.get("since"))
        if not service or not names or since is None:
            raise ValueError("service_metric_names_and_since_required")
        items = await connector.get_metrics(service, names, since, _parse_dt(args.get("until")))
        return [item.model_dump(mode="json") for item in items]

    if provider == "kubernetes":
        service = str(args.get("service") or "").strip()
        if not service:
            raise ValueError("service_required")
        return await KubernetesEvidenceClient().collect_evidence(service)

    connector = SSHVMConnector()
    target = str(args.get("target") or "").strip()
    if not target:
        raise ValueError("target_required")
    if tool == "collect_vm_metrics":
        return await connector.collect_metrics(target)
    if tool == "process_snapshot":
        return await connector.process_snapshot(target)
    service = str(args.get("service") or "").strip()
    if not service:
        raise ValueError("service_required")
    if tool == "service_status":
        return await connector.service_status(target, service)
    if not str(args.get("approval_id") or "").strip():
        raise PermissionError("approval_id_required")
    return await connector.restart_service(target, service)


@app.get("/health")
async def health() -> Dict[str, Any]:
    provider = _provider()
    return {"status": "ok", "provider": provider, "tools": sorted(_TOOL_SCHEMAS[provider])}


@app.post("/mcp")
async def mcp(
    request: JsonRpcRequest,
    authorization: str | None = Header(default=None),
    mcp_protocol_version: str | None = Header(default=None, alias="Mcp-Protocol-Version"),
    mcp_name: str | None = Header(default=None, alias="Mcp-Name"),
) -> Dict[str, Any]:
    if mcp_protocol_version and mcp_protocol_version != settings.MCP_PROTOCOL_VERSION:
        raise HTTPException(status_code=400, detail="unsupported_mcp_protocol_version")

    provider = _provider()
    if request.method == "tools/list":
        _authorize(authorization)
        tools = [{"name": name, **schema} for name, schema in _TOOL_SCHEMAS[provider].items()]
        return {"jsonrpc": "2.0", "id": request.id, "result": {"tools": tools}}

    if request.method != "tools/call":
        return {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32601, "message": "method_not_found"}}

    tool = str(request.params.get("name") or "")
    _authorize(authorization, tool)
    if mcp_name and mcp_name != tool:
        raise HTTPException(status_code=400, detail="mcp_name_mismatch")
    args = request.params.get("arguments") or {}
    if not isinstance(args, dict):
        raise HTTPException(status_code=400, detail="invalid_tool_arguments")
    try:
        content = await _call(provider, tool, args)
    except PermissionError as exc:
        return {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32602, "message": str(exc)}}
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32000, "message": type(exc).__name__}}
    if not isinstance(content, list):
        content = [content]
    return {"jsonrpc": "2.0", "id": request.id, "result": {"content": content}}
