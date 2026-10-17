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
    def _elastic_discovery_window(event_time: datetime, now: datetime) -> tuple[datetime, datetime, Dict[str, Any]]:
        """Allow a bounded future-clock offset without unbounded historical scans.

        A received alert may be ahead of the ingestion clock. Keep the original
        timestamp for audit; widen only this read-only investigation window.
        """
        event_utc = event_time.astimezone(timezone.utc)
        now_utc = now.astimezone(timezone.utc)
        cap = min(300, max(0, int(settings.ELASTIC_ANOMALY_CONTEXT_LOOKAHEAD_SECONDS)))
        skew = (event_utc - now_utc).total_seconds()
        since = max(now_utc - timedelta(hours=6),
                    min(now_utc, event_utc) - timedelta(minutes=20))
        until = min(now_utc + timedelta(seconds=cap),
                    max(now_utc, event_utc + timedelta(seconds=30)))
        return since, until, {
            "timestamp_skew_seconds": int(skew),
            "future_skew_window_seconds": max(0, int((until - now_utc).total_seconds())),
            "time_window_status": (
                "future_skew_capped" if skew > cap else
                "future_skew_included" if until > now_utc else
                "current_time"
            ),
            "window_from": since.isoformat(),
            "window_to": until.isoformat(),
        }

    @staticmethod
    def _runtime_service_candidates(reported_service: str) -> list[str]:
        """Only operator-configured aliases may be tested as real systemd units.

        A log name or LLM text by itself is never a runtime service binding.
        Reverse matching is accepted only when one unambiguous config owner
        declared the reported log label.
        """
        import re
        reported = str(reported_service or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9@_.:-]{2,128}", reported):
            return []
        mapping = settings.ELASTIC_SERVICE_DISCOVERY_ALIASES or {}
        if not isinstance(mapping, dict):
            return [reported]
        keys = [str(key) for key in mapping if str(key).casefold() == reported.casefold()]
        forward = mapping.get(keys[0]) if len(keys) == 1 else []
        aliases = [str(item).strip() for item in forward[:3]] if isinstance(forward, list) else []
        reverse = [
            str(key).strip() for key, values in mapping.items()
            if isinstance(values, list) and any(
                str(value).strip().casefold() == reported.casefold() for value in values
            )
        ]
        if len(reverse) == 1:
            aliases.append(reverse[0])
        elif len(reverse) > 1:
            # Ambiguous operator configuration: do not guess the systemd unit.
            aliases = []
        choices: list[str] = []
        for name in [*aliases, reported]:
            if (re.fullmatch(r"[A-Za-z0-9@_.:-]{2,128}", name)
                    and name.casefold() not in {s.casefold() for s in choices}):
                choices.append(name)
            if len(choices) >= 4:
                break
        return choices

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
        valid_hostname = (
            2 <= len(hostname) <= 253
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", hostname) is not None
            and hostname.casefold() not in {"localhost", "localhost.localdomain"}
        )

        # Each process loads its OWN settings: a target being approved on the
        # VM MCP worker does not imply the API has the same allowlist. Never
        # probe a target missing from the control-plane policy.
        candidate["control_plane_allowlist_count"] = len(allowed)
        candidate["control_plane_target_allowed"] = False
        # Choose a target that is explicitly approved, not simply the first
        # available address. Prefer IP, but an independently allowlisted
        # hostname can be used when the log's IP is not allowed.
        authorized_ips = [
            allowed[ip.casefold()] for ip in valid_ips if ip.casefold() in allowed
        ]
        authorized_hostname = (
            allowed.get(hostname.casefold()) if valid_hostname else None
        )
        if authorized_ips:
            target = authorized_ips[0]
            method = "ip"
        elif authorized_hostname:
            target = authorized_hostname
            method = "hostname"
        else:
            target = None
            method = "ip" if valid_ips else "hostname"
        candidate["verification_method"] = method
        if not target:
            candidate["verification_status"] = (
                "candidate_ip_not_allowlisted" if valid_ips else
                "candidate_hostname_not_allowlisted" if valid_hostname else
                "candidate_hostname_invalid"
            )
            logger.warning(
                "elastic_vm_target_control_plane_denied",
                service=str(service)[:90],
                candidate_has_ip=bool(valid_ips),
                candidate_has_hostname=bool(valid_hostname),
                control_plane_allowlist_count=len(allowed),
                # Target values and secrets are never logged.
            )
            return []
        candidate["control_plane_target_allowed"] = True
        candidate["verification_target"] = target
        from integrations.vm.mcp_client import VMEdgeMCPClient
        client = None
        attempted: list[str] = []
        try:
            client = VMEdgeMCPClient()
            # At most four exact, configured names. A successful read of an
            # allowlisted VM's loaded unit establishes the runtime service;
            # no alias becomes canonical on config alone.
            for runtime_service in SignalGateway._runtime_service_candidates(service):
                attempted.append(runtime_service)
                try:
                    result = await asyncio.wait_for(
                        client.service_status(target, runtime_service),
                        timeout=max(2.0, min(5.0, float(settings.MCP_TIMEOUT_SECONDS))),
                    )
                except PermissionError as exc:
                    # The independent VM MCP worker also enforces its own
                    # allowlists; keep this denial distinct from network IO.
                    denial = str(exc)
                    candidate["verification_status"] = (
                        "vm_worker_target_not_allowlisted"
                        if denial == "vm_target_not_allowed" else
                        "vm_worker_service_not_allowlisted"
                        if denial == "vm_service_not_allowed" else "vm_read_failed"
                    )
                    discovery["runtime_probe_count"] = len(attempted)
                    logger.warning(
                        "elastic_vm_worker_policy_denied",
                        policy_code=candidate["verification_status"],
                        runtime_probe="mapped_alias" if runtime_service != service else "reported",
                    )
                    return []
                except Exception as exc:
                    candidate["verification_status"] = "vm_read_failed"
                    logger.warning("elastic_host_candidate_vm_verify_failed",
                                   error_type=type(exc).__name__,
                                   runtime_probe="mapped_alias" if runtime_service != service else "reported")
                    continue
                if not isinstance(result, dict):
                    candidate["verification_status"] = "vm_result_malformed"
                    continue
                returned_service = str(result.get("service") or "").strip().casefold().removesuffix(".service")
                returned_target = str(result.get("target") or "").strip().casefold()
                active = str(result.get("active_state") or "").strip().lower()
                load = str(result.get("load_state") or "").strip().lower()
                if (result.get("success") is not True
                        or returned_service != runtime_service.casefold().removesuffix(".service")
                        or returned_target != target.casefold()
                        or load != "loaded"
                        or active not in {"active", "failed", "inactive", "activating", "deactivating", "reloading"}):
                    candidate["verification_status"] = "vm_service_identity_not_confirmed"
                    continue
                candidate["verification_status"] = "verified_read_only"
                discovery["status"] = "verified_by_vm_mcp"
                discovery["verified_target"] = target
                discovery["verified_runtime_service"] = runtime_service
                discovery["reported_log_service"] = service
                discovery["mapping_status"] = (
                    "verified_live_vm_mcp" if runtime_service.casefold() != service.casefold()
                    else "same_name_verified"
                )
                discovery["runtime_probe_count"] = len(attempted)
                return [{
                    "type": "telemetry", "source": "vm_mcp",
                    "reference": f"elastic-discovery-vm:{target}:{runtime_service}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw_data": {
                        "diagnostic": "service_status", "success": True,
                        "target": target, "service": runtime_service,
                        "source_service_label": service,
                        "active_state": active, "load_state": load,
                        "sub_state": str(result.get("sub_state") or "")[:60],
                    },
                }]
            discovery["runtime_probe_count"] = len(attempted)
            if not attempted:
                candidate["verification_status"] = "no_valid_runtime_service_name"
            if len(attempted) == 1:
                discovery["mapping_status"] = "no_verified_runtime_alias"
            return []
        except Exception as exc:
            candidate["verification_status"] = "vm_read_failed"
            logger.warning("elastic_host_candidate_vm_verify_failed",
                           error_type=type(exc).__name__)
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
        verified_runtime_mapping: Dict[str, Any] | None = None
        if signal.source == "elasticsearch" and ServiceIdentityResolver.known(signal.service):
            # Read-only log-host discovery at ingest time, *before* RCA routing.
            # Future-skewed webhook timestamps must not shift the query into
            # the future. Host candidates NEVER become approved VM targets.
            from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
            now = datetime.now(timezone.utc)
            since, until, time_metadata = SignalGateway._elastic_discovery_window(
                signal.timestamp, now)
            connector = None
            try:
                connector = ElasticsearchMCPClient()
                host_discovery = await asyncio.wait_for(
                    connector.discover_service_hosts(str(signal.service), since, until),
                    timeout=max(3.0, min(20.0, float(settings.MCP_TIMEOUT_SECONDS))),
                )
                host_discovery["search_strategy"] = "incident_window"
                # The latest alert may be triggered from old logs (e.g. a
                # threshold based on a delayed pipeline). A 20-minute search
                # is not sufficient evidence that no deployment host exists.
                # Only re-search the EXACT reported service and explicit
                # operator-configured aliases, never unfiltered index rows.
                initial_status = str(host_discovery.get("status") or "unknown")
                if (not host_discovery.get("candidates") and initial_status in {
                    "no_matching_logs", "index_has_rows_no_service_time_match",
                    "response_format_unrecognized", "no_host_metadata",
                }):
                    historical_start = now - timedelta(hours=6)
                    historical_end = since
                    if historical_end > historical_start + timedelta(minutes=1):
                        try:
                            historical = await asyncio.wait_for(
                                connector.discover_service_hosts(
                                    str(signal.service), historical_start, historical_end),
                                timeout=max(3.0, min(20.0, float(settings.MCP_TIMEOUT_SECONDS))),
                            )
                            host_discovery["historical_lookup_status"] = str(
                                historical.get("status") or "unknown")[:60]
                            if historical.get("candidates"):
                                historical["recent_lookup_status"] = initial_status
                                historical["historical_lookup_status"] = str(
                                    historical.get("status") or "unknown")[:60]
                                historical["search_strategy"] = "bounded_historical"
                                historical["historical_candidate_requires_live_verification"] = True
                                historical["historical_window_from"] = historical_start.isoformat()
                                historical["historical_window_to"] = historical_end.isoformat()
                                host_discovery = historical
                        except Exception as exc:
                            host_discovery["historical_lookup_status"] = "query_failed"
                            logger.warning(
                                "elastic_historical_service_discovery_failed",
                                service=str(signal.service)[:90],
                                error_type=type(exc).__name__,
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
            host_discovery.update(time_metadata)
            if host_discovery.get("search_strategy") == "bounded_historical":
                # Distinguish the actual scanned historical range from the
                # incident-time bounds retained as original_* for the audit.
                host_discovery["incident_window_from"] = time_metadata["window_from"]
                host_discovery["incident_window_to"] = time_metadata["window_to"]
                host_discovery["window_from"] = host_discovery["historical_window_from"]
                host_discovery["window_to"] = host_discovery["historical_window_to"]
            host_verification_evidence = await SignalGateway._verify_elastic_host_candidate(
                str(signal.service), host_discovery)
            runtime_service = str(host_discovery.get("verified_runtime_service") or "").strip()
            source_label = str(signal.service or "").strip()
            if (host_discovery.get("status") == "verified_by_vm_mcp"
                    and runtime_service and source_label
                    and runtime_service.casefold() != source_label.casefold()
                    and host_verification_evidence):
                blocking, _ = ServiceIdentityResolver.split_conflicts(
                    (resolution.get("service_identity") or {}).get("conflicts"))
                first_evidence = host_verification_evidence[0]
                candidate_mapping = {
                    "source_service": source_label,
                    "runtime_service": runtime_service,
                    "target": host_discovery.get("verified_target"),
                    "evidence_reference": first_evidence.get("reference"),
                    "verification": "vm_mcp_service_status",
                }
                if (not blocking and ServiceIdentityResolver.verified_runtime_alias_matches(
                        source_label, runtime_service,
                        {"verified_runtime_mapping": candidate_mapping},
                        host_verification_evidence)):
                    # This is a new independently checked runtime identity, not
                    # a rewrite of what the original Elastic alert reported.
                    verified_runtime_mapping = candidate_mapping
                    original_identity = dict(resolution["service_identity"])
                    original_identity.update({
                        "service": runtime_service,
                        "status": "verified",
                        "verified": True,
                        "basis": "configured_elastic_alias_verified_by_vm_mcp",
                        "reported_service": source_label,
                        "requires_more_evidence": False,
                    })
                    resolution["service_identity"] = original_identity
                    resolution["asset_context"] = {
                        **resolution["asset_context"],
                        "service": runtime_service,
                        "service_identity_status": "verified",
                        "service_identity_basis": "configured_elastic_alias_verified_by_vm_mcp",
                        "service_identity_unverified": False,
                    }
                    host_discovery["mapping_status"] = "verified_runtime_promoted"
                else:
                    host_discovery["mapping_status"] = "mapping_conflict_or_unverified"
            sole_candidate = ((host_discovery.get("candidates") or [None])[0]
                              if len(host_discovery.get("candidates") or []) == 1 else None)
            logger.info(
                "elastic_ingest_host_discovery",
                service=signal.service, status=host_discovery["status"],
                candidate_count=len(host_discovery.get("candidates") or []),
                result_count=host_discovery.get("result_count", 0),
                verification_method=(sole_candidate or {}).get("verification_method"),
                verification_status=(sole_candidate or {}).get("verification_status"),
            )
        return {
            "asset_context": resolution["asset_context"],
            "host_discovery": host_discovery,
            "verified_runtime_mapping": verified_runtime_mapping,
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
            "verified_runtime_mapping": discovery.get("verified_runtime_mapping"),
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
                "verified_runtime_mapping": discovery.get("verified_runtime_mapping"),
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
