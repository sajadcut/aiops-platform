from __future__ import annotations

import hmac
import json
import time
from datetime import datetime
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from domain.contracts.config import settings
from domain.contracts.logging import configure_logging, logger, redact_value
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


def _validate_production_configuration() -> None:
    if settings.APP_ENV != "production":
        return
    errors: list[str] = []
    provider = _provider()
    if not settings.MCP_SERVER_REQUIRE_AUTH:
        errors.append("MCP_SERVER_REQUIRE_AUTH must be enabled in production")
    if not settings.MCP_BEARER_TOKEN:
        errors.append("MCP_BEARER_TOKEN is required in production")
    if provider == "vm":
        if not settings.MCP_WRITE_BEARER_TOKEN:
            errors.append("VM MCP requires MCP_WRITE_BEARER_TOKEN")
        if settings.MCP_WRITE_BEARER_TOKEN and settings.MCP_WRITE_BEARER_TOKEN == settings.MCP_BEARER_TOKEN:
            errors.append("VM MCP read and write bearer identities must be distinct")
        if not settings.SSH_ENABLED:
            errors.append("VM MCP requires SSH_ENABLED=True on the edge server")
        if not settings.SSH_STRICT_HOST_KEY_CHECKING:
            errors.append("VM MCP requires strict SSH host-key checking")
        if not settings.SSH_KNOWN_HOSTS:
            errors.append("VM MCP requires SSH_KNOWN_HOSTS")
        if not settings.SSH_PRIVATE_KEY_PATH:
            errors.append("VM MCP requires key-based SSH credentials")
        if not settings.SSH_USERNAME.strip() or settings.SSH_USERNAME.strip().lower() == "root":
            errors.append("VM MCP requires a non-root SSH_USERNAME")
        if not settings.VM_ALLOWED_TARGETS:
            errors.append("VM MCP requires a non-empty VM_ALLOWED_TARGETS inventory")
        if not settings.VM_ALLOWED_SERVICES:
            errors.append("VM MCP requires a non-empty VM_ALLOWED_SERVICES allowlist")
    if errors:
        raise RuntimeError("mcp_server_production_configuration_invalid: " + "; ".join(errors))


@app.on_event("startup")
async def startup_validation() -> None:
    _validate_production_configuration()


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


def _log_payload(value: Any) -> Any:
    if not settings.LOG_HTTP_BODY_ENABLED:
        return None
    safe = redact_value(value)
    encoded = json.dumps(safe, default=str, ensure_ascii=False).encode("utf-8")
    if len(encoded) > settings.LOG_HTTP_BODY_MAX_BYTES:
        return {"truncated": True, "size_bytes": len(encoded)}
    return safe


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
    started = time.perf_counter()
    provider = _provider()
    method = request.method
    tool = str(request.params.get("name") or "") if method == "tools/call" else None

    if mcp_protocol_version and mcp_protocol_version != settings.MCP_PROTOCOL_VERSION:
        raise HTTPException(status_code=400, detail="unsupported_mcp_protocol_version")

    logger.info(
        "mcp_request",
        mcp_request_id=request.id,
        provider=provider,
        method=method,
        tool=tool,
        request_payload=_log_payload(request.params),
    )

    if method == "initialize":
        _authorize(authorization)
        requested = str(request.params.get("protocolVersion") or "")
        if requested and requested != settings.MCP_PROTOCOL_VERSION:
            response = {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32602, "message": "unsupported_protocol_version"}}
        else:
            response = {
                "jsonrpc": "2.0",
                "id": request.id,
                "result": {
                    "protocolVersion": settings.MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": f"aiops-{provider}-mcp", "version": settings.APP_VERSION},
                },
            }
    elif method == "notifications/initialized":
        _authorize(authorization)
        response = {"jsonrpc": "2.0", "id": request.id, "result": {}}
    elif method == "tools/list":
        _authorize(authorization)
        tools = [{"name": name, **schema} for name, schema in _TOOL_SCHEMAS[provider].items()]
        response = {"jsonrpc": "2.0", "id": request.id, "result": {"tools": tools}}
    elif method == "tools/call":
        _authorize(authorization, tool)
        if mcp_name and mcp_name != tool:
            raise HTTPException(status_code=400, detail="mcp_name_mismatch")
        args = request.params.get("arguments") or {}
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid_tool_arguments")
        try:
            content = await _call(provider, tool or "", args)
            if not isinstance(content, list):
                content = [content]
            response = {"jsonrpc": "2.0", "id": request.id, "result": {"content": content}}
        except PermissionError as exc:
            response = {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32602, "message": str(exc)}}
        except Exception as exc:
            logger.exception("mcp_tool_call_failed", provider=provider, tool=tool, error_type=type(exc).__name__)
            response = {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32000, "message": "tool_execution_failed"}}
    else:
        response = {"jsonrpc": "2.0", "id": request.id, "error": {"code": -32601, "message": "method_not_found"}}

    logger.info(
        "mcp_response",
        mcp_request_id=request.id,
        provider=provider,
        method=method,
        tool=tool,
        success="error" not in response,
        duration_ms=round((time.perf_counter() - started) * 1000, 3),
        response_payload=_log_payload(response),
    )
    return response
