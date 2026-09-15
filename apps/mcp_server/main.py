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


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: Dict[str, Any] = Field(default_factory=dict)
    id: int | str | None = None


configure_logging()
app = FastAPI(title=f"AIOps MCP Server ({settings.MCP_SERVER_PROVIDER})", docs_url=None, redoc_url=None)
app.add_middleware(HTTPTransactionLoggingMiddleware)
_WRITE_TOOLS = {"restart_service", "reload_service", "start_service"}
_TARGET = {"target": {"type": "string"}}
_SERVICE = {"service": {"type": "string"}}
_PORT = {"port": {"type": "integer", "minimum": 1, "maximum": 65535}}
_APPROVAL_CONTEXT = {
    "approval_id": {"type": "string", "minLength": 1},
    "incident_id": {"type": "string", "minLength": 1},
}

_TOOL_SCHEMAS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "elasticsearch": {
        "search_logs": {"description": "Read Elasticsearch logs for a service/time window", "inputSchema": {"type": "object", "required": ["service", "since"], "properties": {"service": {"type": "string"}, "since": {"type": "string"}, "until": {"type": ["string", "null"]}, "level": {"type": ["string", "null"]}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}}}},
    },
    "prometheus": {
        "query_metrics": {"description": "Read Prometheus metric samples for a service/time window", "inputSchema": {"type": "object", "required": ["service", "metric_names", "since"], "properties": {"service": {"type": "string"}, "metric_names": {"type": "array", "items": {"type": "string"}, "maxItems": 25}, "since": {"type": "string"}, "until": {"type": ["string", "null"]}}}},
        "get_prometheus_alerts": {"description": "Read Prometheus/Alertmanager alerts", "inputSchema": {"type": "object", "properties": {"service": {"type": ["string", "null"]}, "since": {"type": ["string", "null"]}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}}}},
    },
    "kubernetes": {
        "collect_kubernetes_evidence": {"description": "Collect read-only pod/event/log Evidence for a service", "inputSchema": {"type": "object", "required": ["service"], "properties": {"service": {"type": "string"}}}},
    },
    "vm": {
        "collect_vm_metrics": {"description": "Collect allowlisted Linux VM CPU/memory/swap/load/IO metrics", "inputSchema": {"type": "object", "required": ["target"], "properties": dict(_TARGET)}},
        "host_info": {"description": "Read hostname, OS, kernel, uptime and timezone", "inputSchema": {"type": "object", "required": ["target"], "properties": dict(_TARGET)}},
        "disk_status": {"description": "Read filesystem capacity, inode usage and mount status", "inputSchema": {"type": "object", "required": ["target"], "properties": dict(_TARGET)}},
        "network_status": {"description": "Read interface addresses and routing table", "inputSchema": {"type": "object", "required": ["target"], "properties": dict(_TARGET)}},
        "service_status": {"description": "Read normalized systemd service state", "inputSchema": {"type": "object", "required": ["target", "service"], "properties": {**_TARGET, **_SERVICE}}},
        "service_logs": {"description": "Read bounded journal logs for an allowlisted service", "inputSchema": {"type": "object", "required": ["target", "service"], "properties": {**_TARGET, **_SERVICE, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}}},
        "system_logs": {"description": "Read bounded system journal logs", "inputSchema": {"type": "object", "required": ["target"], "properties": {**_TARGET, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}}},
        "process_snapshot": {"description": "Read normalized top process snapshot", "inputSchema": {"type": "object", "required": ["target"], "properties": dict(_TARGET)}},
        "process_status": {"description": "Read normalized state for one allowlisted process/service name", "inputSchema": {"type": "object", "required": ["target", "process"], "properties": {**_TARGET, "process": {"type": "string"}}}},
        "tcp_check": {"description": "Probe TCP connectivity from the VM to a validated host/port", "inputSchema": {"type": "object", "required": ["target", "host", "port"], "properties": {**_TARGET, "host": {"type": "string"}, **_PORT}}},
        "port_listener_status": {"description": "Read local TCP listener/socket ownership for a port", "inputSchema": {"type": "object", "required": ["target", "port"], "properties": {**_TARGET, **_PORT}}},
        "dns_check": {"description": "Resolve a validated hostname from the VM", "inputSchema": {"type": "object", "required": ["target", "hostname"], "properties": {**_TARGET, "hostname": {"type": "string"}}}},
        "route_check": {"description": "Read the route selected for a validated destination", "inputSchema": {"type": "object", "required": ["target", "destination"], "properties": {**_TARGET, "destination": {"type": "string"}}}},
        "firewall_status": {"description": "Read bounded local nftables/firewalld/iptables state", "inputSchema": {"type": "object", "required": ["target"], "properties": dict(_TARGET)}},
        "config_validate": {"description": "Validate configuration through a fixed service diagnostic adapter", "inputSchema": {"type": "object", "required": ["target", "service"], "properties": {**_TARGET, **_SERVICE}}},
        "start_service": {"description": "Start one validated service through approved Execution Service", "inputSchema": {"type": "object", "required": ["target", "service", "approval_id", "incident_id"], "properties": {**_TARGET, **_SERVICE, **_APPROVAL_CONTEXT}}},
        "restart_service": {"description": "Restart one validated service through approved Execution Service", "inputSchema": {"type": "object", "required": ["target", "service", "approval_id", "incident_id"], "properties": {**_TARGET, **_SERVICE, **_APPROVAL_CONTEXT}}},
        "reload_service": {"description": "Reload one validated service through approved Execution Service", "inputSchema": {"type": "object", "required": ["target", "service", "approval_id", "incident_id"], "properties": {**_TARGET, **_SERVICE, **_APPROVAL_CONTEXT}}},
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


def _limit(value: Any, default: int = 100, maximum: int = 500) -> int:
    return min(max(int(value or default), 1), maximum)


def _authorize(authorization: str | None, tool: str | None = None) -> str:
    if settings.APP_ENV == "production" and not settings.MCP_SERVER_REQUIRE_AUTH:
        raise HTTPException(status_code=503, detail="mcp_server_auth_required_in_production")
    if not settings.MCP_SERVER_REQUIRE_AUTH:
        return "mcp-anonymous-development"
    write = tool in _WRITE_TOOLS
    token = settings.MCP_WRITE_BEARER_TOKEN if write else settings.MCP_BEARER_TOKEN
    if not token:
        raise HTTPException(status_code=503, detail="mcp_write_identity_not_configured" if write else "mcp_server_identity_not_configured")
    if not authorization or not hmac.compare_digest(authorization, f"Bearer {token}"):
        raise HTTPException(status_code=401, detail="invalid_mcp_identity")
    return "mcp-write" if write else "mcp-read"


async def _call(provider: str, tool: str, args: Dict[str, Any]) -> Any:
    if tool not in _TOOL_SCHEMAS[provider]:
        raise PermissionError("tool_not_allowed")
    if provider == "elasticsearch":
        connector = ElasticsearchClient()
        service = str(args.get("service") or "").strip()
        since = _parse_dt(args.get("since"))
        if not service or since is None:
            raise ValueError("service_and_since_required")
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
    if tool == "collect_vm_metrics": return await connector.collect_metrics(target)
    if tool == "host_info": return await connector.host_info(target)
    if tool == "disk_status": return await connector.disk_status(target)
    if tool == "network_status": return await connector.network_status(target)
    if tool == "process_snapshot": return await connector.process_snapshot(target)
    if tool == "system_logs": return await connector.system_logs(target, _limit(args.get("limit"), 100, 200))
    if tool == "tcp_check": return await connector.tcp_check(target, str(args.get("host") or ""), int(args.get("port") or 0))
    if tool == "port_listener_status": return await connector.port_listener_status(target, int(args.get("port") or 0))
    if tool == "dns_check": return await connector.dns_check(target, str(args.get("hostname") or ""))
    if tool == "route_check": return await connector.route_check(target, str(args.get("destination") or ""))
    if tool == "firewall_status": return await connector.firewall_status(target)
    if tool == "process_status":
        process = str(args.get("process") or "").strip()
        if not process:
            raise ValueError("process_required")
        return await connector.process_status(target, process)

    service = str(args.get("service") or "").strip()
    if tool in {"service_status", "service_logs", "config_validate", "start_service", "restart_service", "reload_service"} and not service:
        raise ValueError("service_required")
    if tool == "service_status": return await connector.service_status(target, service)
    if tool == "service_logs": return await connector.service_logs(target, service, _limit(args.get("limit"), 100, 200))
    if tool == "config_validate": return await connector.config_validate(target, service)

    approval_id = str(args.get("approval_id") or "").strip()
    incident_id = str(args.get("incident_id") or "").strip()
    if not approval_id:
        raise PermissionError("approval_id_required")
    if not incident_id:
        raise PermissionError("incident_id_required")
    if tool == "start_service": return await connector.start_service(target, service)
    if tool == "restart_service": return await connector.restart_service(target, service)
    if tool == "reload_service": return await connector.reload_service(target, service)
    raise PermissionError("tool_not_allowed")


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
        http_request.state.identity_subject = _authorize(authorization)
        return {"jsonrpc": "2.0", "id": rpc.id, "result": {"protocolVersion": settings.MCP_PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": f"aiops-{provider}-mcp", "version": settings.APP_VERSION}}}
    if rpc.method == "notifications/initialized":
        http_request.state.identity_subject = _authorize(authorization)
        return {"jsonrpc": "2.0", "id": rpc.id, "result": {}}
    if rpc.method == "tools/list":
        http_request.state.identity_subject = _authorize(authorization)
        return {"jsonrpc": "2.0", "id": rpc.id, "result": {"tools": [{"name": name, **schema} for name, schema in _TOOL_SCHEMAS[provider].items()]}}
    if rpc.method != "tools/call":
        return {"jsonrpc": "2.0", "id": rpc.id, "error": {"code": -32601, "message": "method_not_found"}}
    tool = str(rpc.params.get("name") or "")
    http_request.state.identity_subject = _authorize(authorization, tool)
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
