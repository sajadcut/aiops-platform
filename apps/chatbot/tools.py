from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")
_NAMESPACE = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_MAX_TOOL_CALLS = 3


@dataclass(frozen=True, slots=True)
class ToolIntent:
    semantic_name: str
    tool_name: str
    action: str
    target: str
    parameters: dict[str, Any]
    mutating: bool
    risk_level: str


CHAT_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "vm_metrics",
            "description": "Read live CPU, memory, swap, load and IO metrics for one VM through the governed VM MCP. This is a read-only operation and never requires user confirmation.",
            "parameters": {
                "type": "object",
                "required": ["target"],
                "additionalProperties": False,
                "properties": {"target": {"type": "string"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vm_diagnostics",
            "description": "Read one allowlisted VM diagnostic through the governed VM MCP: host_info, disk_status, network_status, process_snapshot or system_logs. disk_status returns every filesystem/mount with blocks, used bytes, available bytes, use_percent and mount path, so use disk_status to answer exact mount questions such as how much free space /app has. This is read-only and never requires user confirmation.",
            "parameters": {
                "type": "object",
                "required": ["target", "diagnostic"],
                "additionalProperties": False,
                "properties": {
                    "target": {"type": "string"},
                    "diagnostic": {"type": "string", "enum": ["host_info", "disk_status", "network_status", "process_snapshot", "system_logs"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vm_service_status",
            "description": "Read the live systemd service state for an allowlisted service on one VM. This is read-only and never requires user confirmation.",
            "parameters": {
                "type": "object",
                "required": ["target", "service"],
                "additionalProperties": False,
                "properties": {"target": {"type": "string"}, "service": {"type": "string"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vm_service_logs",
            "description": "Read bounded logs for an allowlisted service on one VM. This is read-only and never requires user confirmation.",
            "parameters": {
                "type": "object",
                "required": ["target", "service"],
                "additionalProperties": False,
                "properties": {
                    "target": {"type": "string"},
                    "service": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "zabbix_problems",
            "description": "Read current/recent Zabbix problems through the allowlisted Zabbix MCP adapter. This is read-only and never requires user confirmation.",
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "service": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "kubernetes_read",
            "description": "Read Kubernetes data through the governed Kubernetes MCP. Never use kubectl directly. This is read-only and never requires user confirmation.",
            "parameters": {
                "type": "object",
                "required": ["operation", "namespace"],
                "additionalProperties": False,
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": ["list_pods", "pod_status", "deployment_status", "events", "resource_usage", "rollout_state", "service_evidence"],
                    },
                    "namespace": {"type": "string"},
                    "service": {"type": "string"},
                    "resource": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cognia_search",
            "description": "Search the governed Cognia Knowledge RAG for runbooks, policies, procedures, architecture or prior approved knowledge relevant to the operator request. This is knowledge context, not live operational evidence.",
            "parameters": {
                "type": "object",
                "required": ["query"],
                "additionalProperties": False,
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 2000},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cognia_processing_status",
            "description": "Read Cognia processing/lifecycle status for a known knowledge revision. Use this to verify whether a registered/candidate revision is WaitingEligibility, Queued, Processing, ArtifactsReady, Activated, Failed or Obsolete. This is read-only.",
            "parameters": {
                "type": "object",
                "required": ["knowledge_id", "revision_id"],
                "additionalProperties": False,
                "properties": {
                    "knowledge_base_id": {"type": "integer", "minimum": 1},
                    "knowledge_id": {"type": "integer", "minimum": 1},
                    "revision_id": {"type": "integer", "minimum": 1}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "cognia_register_knowledge",
            "description": "Register new governed knowledge in Cognia when the operator explicitly asks to save/register/store information. Backend uses Cognia's documented Knowledge registration contract, KB allowlist, machine identity, server-owned ClientApplication identity and Idempotency-Key. Registration does not imply Activated/Searchable.",
            "parameters": {
                "type": "object",
                "required": ["title", "content"],
                "additionalProperties": False,
                "properties": {
                    "knowledge_base_id": {"type": "integer", "minimum": 1},
                    "knowledge_type": {"type": "string", "enum": ["text"]},
                    "title": {"type": "string", "minLength": 1, "maxLength": 500},
                    "content": {"type": "string", "minLength": 1, "maxLength": 1000000},
                    "scope_type": {
                        "type": "string",
                        "enum": ["general", "clientApplication", "externalSubject"]
                    },
                    "subject_namespace": {"type": "string", "minLength": 1, "maxLength": 64},
                    "external_subject_id": {"type": "string", "minLength": 1, "maxLength": 256},
                    "tag_ids": {
                        "type": "array",
                        "maxItems": 64,
                        "items": {"type": "integer", "minimum": 1}
                    },
                    "category_ids": {
                        "type": "array",
                        "maxItems": 64,
                        "items": {"type": "integer", "minimum": 1}
                    },
                    "metadata": {
                        "type": "object",
                        "maxProperties": 64,
                        "additionalProperties": {"type": "string"}
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cognia_create_revision",
            "description": "Create a new candidate revision for existing Cognia knowledge only when the operator explicitly asks to update existing Cognia knowledge and provides or unambiguously establishes the knowledge id. Backend performs optimistic concurrency using the current candidate revision.",
            "parameters": {
                "type": "object",
                "required": ["knowledge_id", "title", "content"],
                "additionalProperties": False,
                "properties": {
                    "knowledge_base_id": {"type": "integer", "minimum": 1},
                    "knowledge_id": {"type": "integer", "minimum": 1},
                    "title": {"type": "string", "minLength": 1, "maxLength": 500},
                    "content": {"type": "string", "minLength": 1, "maxLength": 1000000},
                    "tag_ids": {
                        "type": "array",
                        "maxItems": 64,
                        "items": {"type": "integer", "minimum": 1}
                    },
                    "category_ids": {
                        "type": "array",
                        "maxItems": 64,
                        "items": {"type": "integer", "minimum": 1}
                    },
                    "metadata": {
                        "type": "object",
                        "maxProperties": 64,
                        "additionalProperties": {"type": "string"}
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vm_service_action",
            "description": "Propose a governed VM service mutation. This only creates an action proposal; it never executes without explicit backend confirmation and durable approval.",
            "parameters": {
                "type": "object",
                "required": ["action", "target", "service"],
                "additionalProperties": False,
                "properties": {
                    "action": {"type": "string", "enum": ["start_service", "restart_service"]},
                    "target": {"type": "string"},
                    "service": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "kubernetes_action",
            "description": "Propose a governed Kubernetes restart, rollback or scale. This never executes directly from the model.",
            "parameters": {
                "type": "object",
                "required": ["action", "target", "namespace"],
                "additionalProperties": False,
                "properties": {
                    "action": {"type": "string", "enum": ["restart_workload", "rollback_workload", "scale_workload"]},
                    "target": {"type": "string"},
                    "namespace": {"type": "string"},
                    "replicas": {"type": "integer", "minimum": 0, "maximum": 100},
                    "revision": {"type": "string"},
                },
            },
        },
    },
]


_ALLOWED_SEMANTIC_TOOLS = {item["function"]["name"] for item in CHAT_TOOL_SCHEMAS}


def max_tool_calls() -> int:
    return _MAX_TOOL_CALLS


def _safe_name(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text or not _SAFE_NAME.fullmatch(text):
        raise ValueError(f"invalid_{field}")
    return text


def _namespace(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not _NAMESPACE.fullmatch(text):
        raise ValueError("invalid_namespace")
    return text


def _bounded_int(value: Any, field: str, minimum: int, maximum: int, default: int) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise ValueError(f"invalid_{field}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid_{field}") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"invalid_{field}")
    return parsed


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ValueError(f"invalid_{field}")
    return text


def _optional_positive_int(value: Any, field: str) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ValueError(f"invalid_{field}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid_{field}") from exc
    if parsed <= 0:
        raise ValueError(f"invalid_{field}")
    return parsed


def _positive_int_list(value: Any, field: str) -> list[int]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError(f"invalid_{field}")
    result: list[int] = []
    for item in value:
        if isinstance(item, bool):
            raise ValueError(f"invalid_{field}")
        try:
            parsed = int(item)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid_{field}") from exc
        if parsed <= 0:
            raise ValueError(f"invalid_{field}")
        result.append(parsed)
    return result


def _flat_string_metadata(value: Any) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict) or len(value) > 64:
        raise ValueError("invalid_metadata")
    result: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = str(key or "").strip()
        if not normalized_key or isinstance(item, (dict, list, tuple, set)):
            raise ValueError("invalid_metadata")
        result[normalized_key] = str(item)
    return result


def parse_tool_call(call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = call.get("function") if isinstance(call, dict) else None
    if not isinstance(function, dict):
        raise ValueError("invalid_llm_tool_call")
    name = str(function.get("name") or "").strip()
    if name not in _ALLOWED_SEMANTIC_TOOLS:
        raise PermissionError("chatbot_tool_not_allowlisted")
    raw = function.get("arguments") or {}
    if isinstance(raw, str):
        try:
            args = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid_llm_tool_arguments") from exc
    else:
        args = raw
    if not isinstance(args, dict):
        raise ValueError("invalid_llm_tool_arguments")
    return name, args


def normalize_tool_intent(name: str, args: dict[str, Any]) -> ToolIntent:
    if name == "vm_metrics":
        return ToolIntent(name, "vm_telemetry", "collect_vm_metrics", _safe_name(args.get("target"), "target"), {}, False, "low")

    if name == "vm_diagnostics":
        target = _safe_name(args.get("target"), "target")
        diagnostic = str(args.get("diagnostic") or "").strip()
        if diagnostic not in {"host_info", "disk_status", "network_status", "process_snapshot", "system_logs"}:
            raise ValueError("invalid_vm_diagnostic")
        params: dict[str, Any] = {}
        if diagnostic == "system_logs":
            params["limit"] = _bounded_int(args.get("limit"), "limit", 1, 200, 50)
        return ToolIntent(name, "vm_telemetry", diagnostic, target, params, False, "low")

    if name in {"vm_service_status", "vm_service_logs"}:
        target = _safe_name(args.get("target"), "target")
        service = _safe_name(args.get("service"), "service")
        action = "service_status" if name == "vm_service_status" else "service_logs"
        params = {"service": service}
        if action == "service_logs":
            params["limit"] = _bounded_int(args.get("limit"), "limit", 1, 200, 50)
        return ToolIntent(name, "vm_telemetry", action, target, params, False, "low")

    if name == "zabbix_problems":
        service = str(args.get("service") or "").strip()
        if service:
            service = _safe_name(service, "service")
        limit = _bounded_int(args.get("limit"), "limit", 1, 100, 25)
        return ToolIntent(name, "zabbix_mcp", "get_alerts", service or "*", {"service": service or None, "limit": limit}, False, "low")

    if name == "kubernetes_read":
        operation = str(args.get("operation") or "").strip()
        allowed = {"list_pods", "pod_status", "deployment_status", "events", "resource_usage", "rollout_state", "service_evidence"}
        if operation not in allowed:
            raise ValueError("invalid_kubernetes_read_operation")
        namespace = _namespace(args.get("namespace"))
        service = str(args.get("service") or "").strip()
        resource = str(args.get("resource") or "").strip()
        if service:
            service = _safe_name(service, "service")
        if resource:
            resource = _safe_name(resource, "resource")
        if operation == "service_evidence" and not service:
            raise ValueError("service_required")
        if operation in {"pod_status", "deployment_status", "rollout_state"} and not resource:
            raise ValueError("resource_required")
        params = {"operation": operation, "namespace": namespace, "service": service or None, "resource": resource or None}
        return ToolIntent(name, "kubernetes_mcp_read", operation, resource or service or namespace, params, False, "low")

    if name == "cognia_search":
        query = _bounded_text(args.get("query"), "query", 2000)
        limit = _bounded_int(args.get("limit"), "limit", 1, 10, 5)
        return ToolIntent(
            name,
            "cognia_knowledge_read",
            "search",
            "cognia",
            {"query": query, "limit": limit},
            False,
            "low",
        )

    if name == "cognia_processing_status":
        kb_id = _optional_positive_int(args.get("knowledge_base_id"), "knowledge_base_id")
        knowledge_id = _optional_positive_int(args.get("knowledge_id"), "knowledge_id")
        revision_id = _optional_positive_int(args.get("revision_id"), "revision_id")
        if knowledge_id is None or revision_id is None:
            raise ValueError("knowledge_and_revision_id_required")
        return ToolIntent(
            name,
            "cognia_knowledge_read",
            "processing_status",
            "cognia",
            {
                "knowledge_base_id": kb_id,
                "knowledge_id": knowledge_id,
                "revision_id": revision_id,
            },
            False,
            "low",
        )

    if name in {"cognia_register_knowledge", "cognia_create_revision"}:
        kb_id = _optional_positive_int(args.get("knowledge_base_id"), "knowledge_base_id")
        title = _bounded_text(args.get("title"), "title", 500)
        content = _bounded_text(args.get("content"), "content", 1_000_000)
        tag_ids = _positive_int_list(args.get("tag_ids"), "tag_ids")
        category_ids = _positive_int_list(args.get("category_ids"), "category_ids")
        metadata = _flat_string_metadata(args.get("metadata"))
        params: dict[str, Any] = {
            "knowledge_base_id": kb_id,
            "title": title,
            "content": content,
            "tag_ids": tag_ids,
            "category_ids": category_ids,
            "metadata": metadata,
        }
        action = "register_knowledge"
        if name == "cognia_register_knowledge":
            knowledge_type = str(args.get("knowledge_type") or "text").strip()
            if knowledge_type != "text":
                raise ValueError("invalid_knowledge_type")
            scope_type = str(args.get("scope_type") or "").strip() or None
            if scope_type not in {None, "general", "clientApplication", "externalSubject"}:
                raise ValueError("invalid_scope_type")
            subject_namespace = str(args.get("subject_namespace") or "").strip()
            external_subject_id = str(args.get("external_subject_id") or "").strip()
            if scope_type == "externalSubject":
                if not subject_namespace or not external_subject_id:
                    raise ValueError("external_subject_requires_namespace_and_id")
                if not _NAMESPACE.fullmatch(subject_namespace.lower()):
                    raise ValueError("invalid_subject_namespace")
                if len(external_subject_id) > 256:
                    raise ValueError("invalid_external_subject_id")
            elif subject_namespace or external_subject_id:
                raise ValueError("external_subject_fields_require_externalSubject_scope")
            params.update(
                {
                    "knowledge_type": knowledge_type,
                    "scope_type": scope_type,
                    "subject_namespace": subject_namespace or None,
                    "external_subject_id": external_subject_id or None,
                }
            )
        else:
            knowledge_id = _optional_positive_int(args.get("knowledge_id"), "knowledge_id")
            if knowledge_id is None:
                raise ValueError("invalid_knowledge_id")
            params["knowledge_id"] = knowledge_id
            action = "create_revision"
        return ToolIntent(
            name,
            "cognia_knowledge_write",
            action,
            "cognia",
            params,
            True,
            "medium",
        )

    if name == "vm_service_action":
        action = str(args.get("action") or "").strip()
        if action not in {"start_service", "restart_service"}:
            raise ValueError("invalid_vm_service_action")
        target = _safe_name(args.get("target"), "target")
        service = _safe_name(args.get("service"), "service")
        return ToolIntent(name, "ssh_vm", action, target, {"service": service}, True, "high")

    if name == "kubernetes_action":
        action = str(args.get("action") or "").strip()
        if action not in {"restart_workload", "rollback_workload", "scale_workload"}:
            raise ValueError("invalid_kubernetes_action")
        target = _safe_name(args.get("target"), "target")
        namespace = _namespace(args.get("namespace"))
        params: dict[str, Any] = {"namespace": namespace}
        if action == "scale_workload":
            if "replicas" not in args:
                raise ValueError("replicas_required")
            params["replicas"] = _bounded_int(args.get("replicas"), "replicas", 0, 100, 1)
        if action == "rollback_workload" and args.get("revision") not in (None, ""):
            params["revision"] = _safe_name(args.get("revision"), "revision")
        return ToolIntent(name, "kubernetes_mcp", action, target, params, True, "high")

    raise PermissionError("chatbot_tool_not_allowlisted")
