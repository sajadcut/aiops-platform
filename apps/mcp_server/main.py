from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from apps.api.http_logging import HTTPTransactionLoggingMiddleware
from domain.contracts.config import settings
from domain.contracts.logging import configure_logging, logger
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


configure_logging()
app = FastAPI(title=f"AIOps MCP Server ({settings.MCP_SERVER_PROVIDER})", docs_url=None, redoc_url=None)
app.add_middleware(HTTPTransactionLoggingMiddleware)
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


def _authorize(authorization: str | None, tool: str | None = None) -> str:
    if settings.APP_ENV == "production" and not settings.MCP_SERVER_REQUIRE_AUTH:
        raise HTTPException(status_code=503, detail="mcp_server_auth_required_in_production")
    if not settings.MCP_SERVER_REQUIRE_AUTH:
        return "mcp-anonymous-development"
    write = tool in _WRITE_TOOLS
    token = settings.MCP_WRITE_BEARER_TOKEN if write else settings.MCP_BEARER_TOKEN
    if not token:
        detail = "mcp_write_identity_not_configured" if write else "mcp_server_identity_not_configured"
        raise HTTPException(status_code=503, detail=detail)
    expected = f"Bearer {token}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid_mcp_identity")
    return "mcp-write" if write else "mcp-read"


async def _call(provider: str, tool: str, args: Dict[str, Any]) -> Any:
    if tool not in _TOOL_SCHEMAS[provider]:
        raise PermissionError("tool_not_allowed")

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


def _validate_production_server() -> None:
    if settings.APP_ENV != "production":
        return
    errors: list[str] = []
    provider = _provider()
    if not settings.MCP_SERVER_REQUIRE_AUTH:
        errors.append("MCP_SERVER_REQUIRE_AUTH must be true")
    if not settings.MCP_BEARER_TOKEN:
        errors.append("MCP_BEARER_TOKEN is required")
    if provider == "vm":
        if not settings.MCP_WRITE_BEARER_TOKEN:
            errors.append("MCP_WRITE_BEARER_TOKEN is required for VM writes")
        elif settings.MCP_WRITE_BEARER_TOKEN == settings.MCP_BEARER_TOKEN:
            errors.append("VM read and write identities must be distinct")
        try:
            SSHVMConnector()
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise RuntimeError("mcp_server_configuration_invalid:" + ";".join(errors))


@app.on_event("startup")
async def startup_event() -> None:
    _validate_production_server()
    logger.info("mcp_server_started", provider=_provider(), protocol=settings.MCP_PROTOCOL_VERSION)


@app.get("/health")
async def health() -> Dict[str, Any]:
    provider = _provider()
    return {"status": "ok", "provider": provider, "tools": sorted(_TOOL_SCHEMAS[provider])}


@app.post("/mcp")
async def mcp(
    rpc: JsonRpcRequest,
    http_request: Request,
    authorization: str | None = Header(default=None),
    mcp_protocol_version: str | None = Header(default=None, alias="Mcp-Protocol-Version"),
    mcp_name: str | None = Header(default=None, alias="Mcp-Name"),
) -> Dict[str, Any]:
    if mcp_protocol_version and mcp_protocol_version != settings.MCP_PROTOCOL_VERSION:
        raise HTTPException(status_code=400, detail="unsupported_mcp_protocol_version")

    provider = _provider()
    if rpc.method == "initialize":
        actor = _authorize(authorization)
        http_request.state.identity_subject = actor
        return {
            "jsonrpc": "2.0",
            "id": rpc.id,
            "result": {
                "protocolVersion": settings.MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": f"aiops-{provider}-mcp", "version": settings.APP_VERSION},
            },
        }

    if rpc.method == "notifications/initialized":
        actor = _authorize(authorization)
        http_request.state.identity_subject = actor
        return {"jsonrpc": "2.0", "id": rpc.id, "result": {}}

    if rpc.method == "tools/list":
        actor = _authorize(authorization)
        http_request.state.identity_subject = actor
        tools = [{"name": name, **schema} for name, schema in _TOOL_SCHEMAS[provider].items()]
        return {"jsonrpc": "2.0", "id": rpc.id, "result": {"tools": tools}}

    if rpc.method != "tools/call":
        return {"jsonrpc": "2.0", "id": rpc.id, "error": {"code": -32601, "message": "method_not_found"}}

    tool = str(rpc.params.get("name") or "")
    actor = _authorize(authorization, tool)
    http_request.state.identity_subject = actor
    if mcp_name and mcp_name != tool:
        raise HTTPException(status_code=400, detail="mcp_name_mismatch")
    args = rpc.params.get("arguments") or {}
    if not isinstance(args, dict):
        raise HTTPException(status_code=400, detail="invalid_tool_arguments")
    try:
        content = await _call(provider, tool, args)
    except PermissionError as exc:
        logger.warning("mcp_tool_call_denied", provider=provider, tool=tool, error_type=type(exc).__name__)
        return {"jsonrpc": "2.0", "id": rpc.id, "error": {"code": -32602, "message": str(exc)}}
    except Exception as exc:
        logger.exception("mcp_tool_call_failed", provider=provider, tool=tool, error_type=type(exc).__name__)
        return {"jsonrpc": "2.0", "id": rpc.id, "error": {"code": -32000, "message": "tool_call_failed"}}
    if not isinstance(content, list):
        content = [content]
    return {"jsonrpc": "2.0", "id": rpc.id, "result": {"content": content}}
