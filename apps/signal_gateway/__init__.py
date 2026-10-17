from __future__ import annotations

import asyncio

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from apps.context_service.asset_identity import AssetIdentityResolver
from apps.context_service.knowledge_topology import KnowledgeTopologyResolver
from apps.context_service.knowledge_relevance import filter_service_knowledge
from apps.context_service.service_identity import ServiceIdentityResolver
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.learning_runtime import LearningDurableWorkflowRuntime
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.rag_service import KnowledgeRAGService
from apps.signal_gateway.correlation import build_correlation_identity
from apps.signal_gateway.received_signal import capture_received_signal
from integrations.zabbix.webhook_contract import normalize_zabbix_payload, zabbix_event_time, zabbix_tags
from domain.contracts.config import settings
from domain.contracts.logging import logger


SignalSource = Literal["zabbix", "elasticsearch", "prometheus", "kubernetes", "security", "manual"]


class OperationalSignal(BaseModel):
    source: SignalSource
    source_id: str = Field(min_length=1, max_length=512)
    signal_type: str = Field(min_length=1, max_length=128)
    severity: str = Field(default="unknown", max_length=64)
    summary: str = Field(min_length=1, max_length=4000)
    service: Optional[str] = Field(default=None, max_length=512)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    correlation_key: Optional[str] = Field(default=None, max_length=512)

    @field_validator("source", mode="before")
    @classmethod
    def normalize_source(cls, value: Any):
        source = str(value or "").strip().lower()
        aliases = {"elk": "elasticsearch", "elastic": "elasticsearch", "alertmanager": "prometheus", "prom": "prometheus", "k8s": "kubernetes"}
        return aliases.get(source, source)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: Any):
        severity = str(value or "unknown").strip().lower()
        aliases = {"disaster": "critical", "average": "medium", "warning": "medium", "information": "low"}
        return aliases.get(severity, severity)

    def to_evidence(self) -> Dict[str, Any]:
        evidence_type = "alert"
        kind = self.signal_type.lower()
        if self.source == "elasticsearch" and self.raw_data.get("elastic_alert_kind") == "ml_anomaly":
            evidence_type = "alert"
        elif self.source == "prometheus" and self.raw_data.get("prometheus_alert_kind") == "alertmanager":
            evidence_type = "alert"
        elif self.source == "elasticsearch" or "log" in kind or "anomaly" in kind:
            evidence_type = "log" if self.source == "elasticsearch" else "event"
        elif self.source == "prometheus" or "metric" in kind:
            evidence_type = "metric"
        elif self.source == "kubernetes":
            evidence_type = "event"
        return {
            "type": evidence_type,
            "source": self.source,
            "reference": self.source_id,
            "timestamp": self.timestamp.isoformat(),
            "confidence": 1.0,
            "raw_data": {
                **self.raw_data,
                "signal_type": self.signal_type,
                "signal_summary": self.summary,
                "signal_severity": self.severity,
                "service": self.service or self.raw_data.get("service"),
            },
        }


class SignalGateway:
    """Source-agnostic, race-safe entry point for operational signals.

    Every new signal is also searched against Cognia before correlation. Cognia
    may supply a service/topology discovery hint when the trigger itself is
    sparse, while live signal metadata remains authoritative on conflicts.
    """

    @staticmethod
    def _append_trigger_to_checkpoint(state: Dict[str, Any], signal: OperationalSignal, evidence: Dict[str, Any]) -> None:
        context = state.setdefault("context", {})
        triggers = list(context.get("trigger_evidence") or [])
        if not any(str(item.get("source")) == signal.source and str(item.get("reference")) == signal.source_id for item in triggers if isinstance(item, dict)):
            triggers.append(evidence)
        context["trigger_evidence"] = triggers
        evidence_items = list(context.get("evidence") or [])
        if not any(str(item.get("source")) == signal.source and str(item.get("reference")) == signal.source_id for item in evidence_items if isinstance(item, dict)):
            evidence_items.append(evidence)
        context["evidence"] = evidence_items

    @staticmethod
    async def _existing_state(checkpoints: WorkflowCheckpointStore, incident_id: str) -> Dict[str, Any]:
        checkpoint = await checkpoints.load(incident_id)
        state = dict((checkpoint or {}).get("state") or {})
        state["incident_id"] = incident_id
        return state

    @staticmethod
    async def _verify_elastic_host_candidate(service: str, discovery: Dict[str, Any]) -> list[Dict[str, Any]]:
        """Verify one log host with a read-only service_status on an *allowlisted* VM.

        A log shipper hostname or an LLM suggestion never grants an action target.
        Verification proves only service identity and current state; writes still
        require the independent incident binding, policy and human Approval.
        """
        candidates = discovery.get("candidates") or []
        if len(candidates) != 1:
            return []
        candidate = candidates[0]
        if not settings.VM_MCP_URL:
            candidate["verification_status"] = "vm_mcp_not_configured"
            return []

        # A hostname from Elastic is untrusted telemetry. Never discover or
        # connect to an arbitrary host: the name/IP must exactly match the VM
        # worker's preconfigured target allowlist before ANY network probe.
        # Return the spelling from the allowlist because the SSH worker uses
        # case-sensitive target authorization.
        import ipaddress
        import re
        allowed = {
            str(item).strip().casefold(): str(item).strip()
            for item in settings.SSH_ALLOWED_TARGETS if str(item).strip()
        }
        raw_ips = candidate.get("ip_addresses") or []
        if isinstance(raw_ips, str):
            raw_ips = [raw_ips]
        valid_ips: list[str] = []
        for value in (raw_ips if isinstance(raw_ips, list) else [])[:6]:
            try:
                parsed = ipaddress.ip_address(str(value).strip())
                if not (parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast):
                    valid_ips.append(str(parsed))
            except ValueError:
                continue
        hostname = str(candidate.get("hostname") or "").strip()
        # No IP in the log? Try the exact allowlisted hostname via read-only
        # VM MCP service_status. DNS and SSH host-key checks remain on the VM
        # MCP worker; the control plane does not resolve untrusted hostnames.
        via_hostname = not valid_ips
        if via_hostname:
            candidate["verification_method"] = "hostname"
            if not (2 <= len(hostname) <= 253
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", hostname)
                    and hostname.lower() not in {"localhost", "localhost.localdomain"}):
                candidate["verification_status"] = "candidate_hostname_invalid"
                return []
            options = [hostname]
        else:
            candidate["verification_method"] = "ip"
            options = valid_ips

        target = next((allowed[value.casefold()] for value in options
                       if value.casefold() in allowed), None)
        if not target:
            candidate["verification_status"] = (
                "candidate_hostname_not_allowlisted" if via_hostname
                else "candidate_ip_not_allowlisted"
            )
            return []
        candidate["verification_target"] = target
        from integrations.vm.mcp_client import VMEdgeMCPClient
        client = None
        try:
            client = VMEdgeMCPClient()
            result = await asyncio.wait_for(
                client.service_status(target, service),
                timeout=max(3.0, min(20.0, float(settings.MCP_TIMEOUT_SECONDS))),
            )
            if not isinstance(result, dict):
                candidate["verification_status"] = "vm_result_malformed"
                return []
            returned_service = str(result.get("service") or "").strip().casefold().removesuffix(".service")
            returned_target = str(result.get("target") or "").strip().casefold()
            active = str(result.get("active_state") or "").strip().lower()
            load = str(result.get("load_state") or "").strip().lower()
            if (result.get("success") is not True or returned_service != service.casefold().removesuffix(".service")
                    or returned_target != target.casefold()
                    or load != "loaded"
                    or active not in {"active", "failed", "inactive", "activating", "deactivating", "reloading"}):
                candidate["verification_status"] = "vm_service_identity_not_confirmed"
                return []
            candidate["verification_status"] = "verified_read_only"
            discovery["status"] = "verified_by_vm_mcp"
            discovery["verified_target"] = target
            return [{
                "type": "telemetry", "source": "vm_mcp",
                "reference": f"elastic-discovery-vm:{target}:{service}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": {
                    "diagnostic": "service_status", "success": True,
                    "target": target, "service": service,
                    "active_state": active, "load_state": load,
                    "sub_state": str(result.get("sub_state") or "")[:60],
                },
            }]
        except Exception as exc:
            candidate["verification_status"] = "vm_read_failed"
            logger.warning("elastic_host_candidate_vm_verify_failed", error_type=type(exc).__name__)
            return []
        finally:
            if client is not None:
                try:
                    await client.close()
                except Exception:
                    logger.debug("elastic_host_vm_client_close_failed")

    @staticmethod
    async def _knowledge_assisted_asset(signal: OperationalSignal, trigger_evidence: Dict[str, Any]) -> Dict[str, Any]:
        live_asset = AssetIdentityResolver.resolve([trigger_evidence], signal.service)
        incident = {
            "service": signal.service,
            "summary": signal.summary,
            "context": {
                "url": signal.raw_data.get("url") or signal.raw_data.get("endpoint"),
                "fqdn": signal.raw_data.get("fqdn"),
                "host": (
                    signal.raw_data.get("host")
                    if isinstance(signal.raw_data.get("host"), str)
                    else None
                ),
            },
        }
        query = KnowledgeTopologyResolver.build_discovery_query(incident)
        expected_fqdns = ServiceIdentityResolver.expected_fqdns(
            summary=signal.summary, context=signal.raw_data,
        )
        knowledge_results = []
        knowledge_status: Dict[str, Any] = {
            "provider": "cognia",
            "status": "not_queried",
            "count": 0,
            "phase": "signal_asset_discovery",
        }
        try:
            raw_results = await KnowledgeRAGService().search(
                query,
                limit=min(20, max(5, settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS * 3))
                    if signal.service else settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS,
            )
            knowledge_results, relevance_audit = filter_service_knowledge(
                raw_results, expected_service=signal.service,
                expected_fqdns=expected_fqdns,
                purpose="signal_asset_discovery",
            )
            knowledge_results = knowledge_results[:settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS]
            knowledge_status = {
                "provider": "cognia",
                "status": ("filtered_empty" if relevance_audit["rejected_count"] and not knowledge_results
                           else "available" if knowledge_results else "empty"),
                "count": len(knowledge_results),
                "phase": "signal_asset_discovery",
                "relevance": relevance_audit,
            }
            if relevance_audit["rejected_count"]:
                logger.info("cognia_service_relevance_filtered",
                            service=signal.service, phase="signal_asset_discovery",
                            accepted=len(knowledge_results),
                            rejected=relevance_audit["rejected_count"],
                            rejected_refs=[x["source_id"] for x in relevance_audit["rejected"]])
        except Exception as exc:
            knowledge_status = {
                "provider": "cognia",
                "status": "error",
                "code": type(exc).__name__,
                "count": 0,
                "phase": "signal_asset_discovery",
            }
            logger.warning(
                "signal_asset_discovery_knowledge_query_failed",
                source=signal.source,
                error_type=type(exc).__name__,
            )

        topology = KnowledgeTopologyResolver.resolve(
            knowledge_results,
            expected_fqdns=expected_fqdns,
            expected_service=signal.service,
        )
        resolution = ServiceIdentityResolver.resolve(
            source_service=signal.service,
            live_asset=live_asset,
            knowledge_topology=topology,
            expected_fqdns=expected_fqdns,
        )
        host_discovery: Dict[str, Any] = {"status": "not_requested", "candidates": [], "result_count": 0}
        host_verification_evidence: list[Dict[str, Any]] = []
        if signal.source == "elasticsearch" and ServiceIdentityResolver.known(signal.service):
            # Read-only log-host discovery at ingest time, *before* RCA routing.
            # Future-skewed webhook timestamps must not shift the query into
            # the future. Host candidates NEVER become approved VM targets.
            from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
            now = datetime.now(timezone.utc)
            event_time = signal.timestamp.astimezone(timezone.utc)
            since = max(now - timedelta(hours=6), min(now, event_time) - timedelta(minutes=20))
            connector = None
            try:
                connector = ElasticsearchMCPClient()
                host_discovery = await asyncio.wait_for(
                    connector.discover_service_hosts(str(signal.service), since, now),
                    timeout=max(3.0, min(20.0, float(settings.MCP_TIMEOUT_SECONDS))),
                )
            except Exception as exc:
                host_discovery = {
                    "status": "query_failed", "error_type": type(exc).__name__[:60],
                    "candidates": [], "result_count": 0,
                }
            finally:
                if connector is not None:
                    try:
                        await connector.close()
                    except Exception:
                        logger.debug("elastic_host_discovery_client_close_failed")
            host_verification_evidence = await SignalGateway._verify_elastic_host_candidate(
                str(signal.service), host_discovery)
            logger.info(
                "elastic_ingest_host_discovery",
                service=signal.service, status=host_discovery["status"],
                candidate_count=len(host_discovery.get("candidates") or []),
                result_count=host_discovery.get("result_count", 0),
            )
        return {
            "asset_context": resolution["asset_context"],
            "host_discovery": host_discovery,
            "host_verification_evidence": host_verification_evidence,
            "service_identity": resolution["service_identity"],
            "live_asset_context": live_asset,
            "topology_context": resolution["topology_context"],
            "knowledge_results": knowledge_results,
            "knowledge_status": knowledge_status,
            "knowledge_discovery_query": query,
        }

    @staticmethod
    async def ingest(session, signal: OperationalSignal) -> Dict[str, Any]:
        trigger_evidence = signal.to_evidence()
        discovery = await SignalGateway._knowledge_assisted_asset(signal, trigger_evidence)
        asset = dict(discovery.get("asset_context") or {})
        # One shared authority policy across webhooks, ContextBuilder and
        # orchestration. Hostnames are kept distinct from service identity.
        resolved_service = str(discovery["service_identity"]["service"])
        correlation = build_correlation_identity(
            service=resolved_service,
            signal_type=signal.signal_type,
            summary=signal.summary,
            asset=asset,
            explicit_key=signal.correlation_key,
        )
        correlation_key = signal.correlation_key or correlation.fingerprint or f"{resolved_service}:{signal.source}:{signal.source_id}"
        incidents = IncidentRepository(session)
        checkpoints = WorkflowCheckpointStore(session)

        existing_incident_id = await incidents.find_incident_by_evidence_reference(source=signal.source, reference=signal.source_id)
        if existing_incident_id:
            state = await SignalGateway._existing_state(checkpoints, existing_incident_id)
            state.update({
                "trigger_source": signal.source,
                "trigger_signal_type": signal.signal_type,
                "correlation_key": correlation_key,
                "deduplicated": True,
                "deduplication_reason": "same_source_event_reference",
                "correlated": False,
            })
            return state

        # Every source event gets its own transaction lock, even when it is not
        # eligible for cross-source correlation. This closes exact retry races.
        await incidents.acquire_correlation_lock(f"event:{signal.source}:{signal.source_id}")
        existing_incident_id = await incidents.find_incident_by_evidence_reference(source=signal.source, reference=signal.source_id)
        if existing_incident_id:
            state = await SignalGateway._existing_state(checkpoints, existing_incident_id)
            state.update({
                "trigger_source": signal.source,
                "trigger_signal_type": signal.signal_type,
                "correlation_key": correlation_key,
                "deduplicated": True,
                "deduplication_reason": "same_source_event_reference_after_lock",
                "correlated": False,
            })
            return state

        if settings.SIGNAL_CORRELATION_ENABLED and correlation.fingerprint:
            await incidents.acquire_correlation_lock(f"correlation:{correlation.fingerprint}")
            existing_incident_id = await incidents.find_correlated_open_incident(
                fingerprint=correlation.fingerprint,
                service=resolved_service,
                since=signal.timestamp - timedelta(seconds=settings.SIGNAL_CORRELATION_WINDOW_SECONDS),
                limit=settings.SIGNAL_CORRELATION_CANDIDATE_LIMIT,
            )
            if existing_incident_id:
                signal_metadata = {
                    "source": signal.source,
                    "source_id": signal.source_id,
                    "signal_type": signal.signal_type,
                    "severity": signal.severity,
                    "timestamp": signal.timestamp.isoformat(),
                    "correlation_fingerprint": correlation.fingerprint,
                    "signal_family": correlation.signal_family,
                }
                await incidents.attach_correlated_signal(existing_incident_id, evidence=trigger_evidence, signal_metadata=signal_metadata)
                checkpoint = await checkpoints.load(existing_incident_id)
                state = dict((checkpoint or {}).get("state") or {})
                if state:
                    SignalGateway._append_trigger_to_checkpoint(state, signal, trigger_evidence)
                    correlated_signals = list(state.get("correlated_signals") or [])
                    identity = (signal.source, signal.source_id)
                    if identity not in {(str(item.get("source")), str(item.get("source_id"))) for item in correlated_signals if isinstance(item, dict)}:
                        correlated_signals.append(signal_metadata)
                    state["correlated_signals"] = correlated_signals[-100:]
                    await checkpoints.save(existing_incident_id, state, status=str((checkpoint or {}).get("status") or "paused"))
                else:
                    await incidents.commit()
                state.update({
                    "incident_id": existing_incident_id,
                    "trigger_source": signal.source,
                    "trigger_signal_type": signal.signal_type,
                    "correlation_key": correlation_key,
                    "deduplicated": True,
                    "deduplication_reason": "cross_source_correlation",
                    "correlated": True,
                    "correlation_fingerprint": correlation.fingerprint,
                })
                return state

        incident_id = str(uuid4())
        correlation_context = {
            "fingerprint": correlation.fingerprint,
            "signal_family": correlation.signal_family,
            "scope": correlation.scope,
            "explicit": correlation.explicit,
            "window_seconds": settings.SIGNAL_CORRELATION_WINDOW_SECONDS,
        }
        incident_context = {
            "source": signal.source,
            "severity": signal.severity,
            "service": resolved_service,
            "summary": signal.summary,
            "service_identity_basis": discovery["service_identity"]["basis"],
            "service_identity_status": discovery["service_identity"]["status"],
            "host_discovery_status": (discovery.get("host_discovery") or {}).get("status"),
            "host_candidate_count": len((discovery.get("host_discovery") or {}).get("candidates") or []),
            "source_host": asset.get("hostname"),
            "signal_type": signal.signal_type,
            "correlation_key": correlation_key,
        }
        initial_state = {
            "incident_id": incident_id,
            "service_name": resolved_service,
            "evidence_summary": f"Trigger source={signal.source}; type={signal.signal_type}; severity={signal.severity}; {signal.summary}",
            # Persist the independent VM read before the graph can overwrite its live collection.
            "live_evidence": {"evidence": list(discovery.get("host_verification_evidence") or [])},
            "context": {
                "incident": incident_context,
                "service": resolved_service,
                "asset_context": asset,
                "host_discovery": discovery.get("host_discovery", {}),
                "service_identity": discovery["service_identity"],
                "live_asset_context": discovery.get("live_asset_context"),
                "topology_context": discovery.get("topology_context"),
                "knowledge_results": discovery.get("knowledge_results", []),
                "knowledge_status": discovery.get("knowledge_status", {}),
                "knowledge_discovery_query": discovery.get("knowledge_discovery_query"),
                "correlation": correlation_context,
                "related_signals": [],
                "trigger_signal": signal.model_dump(mode="json"),
                "trigger_evidence": [trigger_evidence],
                "evidence": [trigger_evidence] + list(discovery.get("host_verification_evidence") or []),
            },
            "messages": [],
            "findings": [],
            "confidence": 0.0,
        }
        result = await LearningDurableWorkflowRuntime(session).start(initial_state)
        result.update({
            "trigger_source": signal.source,
            "trigger_signal_type": signal.signal_type,
            "correlation_key": correlation_key,
            "correlation_fingerprint": correlation.fingerprint,
            "deduplicated": False,
            "correlated": False,
        })
        return result


def signal_from_elasticsearch(payload: Dict[str, Any]) -> OperationalSignal:
    source = payload.get("_source") if isinstance(payload.get("_source"), dict) else payload
    service = source.get("service")
    if isinstance(service, dict):
        service = service.get("name")
    rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
    event = source.get("event") if isinstance(source.get("event"), dict) else {}
    event_id = payload.get("_id") or event.get("id") or source.get("id")
    # Kibana's "query matched" is a *status*, not a unique alert identifier.
    # Stable incident identity uses event context and source timestamp.
    if str(event_id or "").strip().casefold() in {"query matched", "matched", "unknown", ""}:
        import hashlib
        import json
        material = {
            "service": service, "event": event, "rule": rule,
            "timestamp": source.get("timestamp") or source.get("@timestamp"),
            "observed_count": source.get("observed_count"),
            "message": source.get("message"),
        }
        event_id = "elastic-event:" + hashlib.sha256(
            json.dumps(material, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()
    return OperationalSignal(
        source="elasticsearch",
        source_id=str(event_id),
        signal_type=str(event.get("action") or event.get("kind") or rule.get("category") or "log_anomaly"),
        severity=str(source.get("severity") or rule.get("severity") or "unknown"),
        summary=str(source.get("message") or rule.get("name") or "Elasticsearch anomaly detected"),
        service=str(service) if service else None,
        correlation_key=source.get("correlation_key") or event.get("correlation_key"),
        raw_data={**source, "_received_payload": capture_received_signal(payload)},
    )


def signal_from_prometheus(payload: Dict[str, Any]) -> OperationalSignal:
    labels = payload.get("labels") or {}
    annotations = payload.get("annotations") or {}
    return OperationalSignal(
        source="prometheus",
        source_id=str(payload.get("fingerprint") or labels.get("alertname") or uuid4()),
        signal_type=str(labels.get("alertname") or "metric_alert"),
        severity=str(labels.get("severity") or "unknown"),
        summary=str(annotations.get("summary") or annotations.get("description") or labels.get("alertname") or "Prometheus alert"),
        service=labels.get("service") or labels.get("service_name") or labels.get("app"),
        correlation_key=labels.get("correlation_key") or labels.get("incident_key"),
        raw_data={"labels": labels, "annotations": annotations, **{k: v for k, v in payload.items() if k not in {"labels", "annotations"}}, "_received_payload": capture_received_signal(payload)},
    )


def _zabbix_service_from_tags(payload: Dict[str, Any]) -> Optional[str]:
    candidates = zabbix_tags(payload.get("tags"))
    host = payload.get("host")
    if isinstance(host, dict):
        candidates.extend(zabbix_tags(host.get("tags")))
    for item in candidates:
        if item["tag"] in {"service", "service_name", "app"} and item["value"]:
            return item["value"]
    return None


def signal_from_zabbix(payload: Dict[str, Any]) -> OperationalSignal:
    # The Zabbix Team Guide v1.1 emits a flat JSON payload with a separate
    # tags array. Keep all original fields for Evidence; normalize only the
    # identity data that is explicitly supplied by the Webhook.
    normalized = normalize_zabbix_payload(payload)
    raw = dict(normalized)
    host_value = normalized.get("host") or normalized.get("hostname")
    if host_value and not isinstance(host_value, dict):
        raw["host"] = {
            "host": str(host_value),
            "name": str(normalized.get("host_name") or host_value),
            "hostid": str(normalized.get("hostid") or ""),
        }
    # A Web Scenario monitoring host is not the monitored service.
    service = normalized.get("service") or _zabbix_service_from_tags(normalized)
    event_time = zabbix_event_time(normalized.get("timestamp"))
    args = {
        "source": "zabbix",
        "source_id": str(normalized["eventid"]),
        "signal_type": str(normalized.get("trigger") or normalized.get("name") or "zabbix_problem"),
        "severity": str(normalized.get("severity") or "unknown"),
        "summary": str(normalized.get("name") or normalized.get("message") or "Zabbix problem detected"),
        "service": str(service) if service else None,
        "correlation_key": normalized.get("correlation_key") or normalized.get("incident_key"),
        "raw_data": raw,
    }
    if event_time is not None:
        args["timestamp"] = event_time
    return OperationalSignal(**args)
