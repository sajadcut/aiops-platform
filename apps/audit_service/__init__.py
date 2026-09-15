"""Operational audit trail service with durable flush support and secret redaction."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from domain.contracts.logging import log_workflow_step
from domain.contracts.redaction import redact


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    event_type: str
    actor: str
    incident_id: Optional[str]
    action: Optional[str]
    status: str
    metadata: Dict[str, Any]
    created_at: str


class AuditService:
    _events: List[AuditEvent] = []

    @classmethod
    def _redact(cls, value: Any, key: Optional[str] = None) -> Any:
        return redact(value, key)

    @staticmethod
    def _timeline_stage(event_type: str) -> str:
        event = str(event_type or "").lower()
        if event.startswith(("context", "trigger", "signal", "asset_", "pre_execution_evidence", "agent_evidence")):
            return "context_evidence"
        if event.startswith("triage"):
            return "triage"
        if event.startswith(("specialist", "agent_handoff")):
            return "specialist_agents"
        if event.startswith("rca"):
            return "rca"
        if event.startswith(("evaluation", "decision_blocked_by_evaluator")):
            return "evaluator"
        if event.startswith("decision"):
            return "decision"
        if event.startswith("approval"):
            return "approval"
        if event.startswith(("execution", "runbook_execution", "remediation")):
            return "execution"
        if event.startswith("verification"):
            return "verification"
        if event.startswith("memory"):
            return "memory"
        return "governance"

    @staticmethod
    def _timeline_component(event_type: str, actor: str) -> str:
        stage = AuditService._timeline_stage(event_type)
        return {
            "context_evidence": "context_evidence_layer",
            "triage": "triage_agent",
            "specialist_agents": "specialist_agents",
            "rca": "llm_rca",
            "evaluator": "evaluation_gate",
            "decision": "decision_engine",
            "approval": "approval_service",
            "execution": "execution_service",
            "verification": "verification_service",
            "memory": "operational_memory",
        }.get(stage, str(actor or "audit_service"))

    @staticmethod
    def _timeline_status(event_type: str, status: str) -> str:
        explicit = str(status or "recorded").strip().lower()
        event = str(event_type or "").lower()
        if explicit not in {"recorded", ""}:
            return explicit
        if "failed" in event or "error" in event:
            return "failed"
        if "blocked" in event or "rejected" in event:
            return "blocked"
        if "required" in event or "pending" in event:
            return "waiting"
        return "completed"

    @classmethod
    def record(
        cls,
        event_type: str,
        actor: str,
        incident_id: Optional[str] = None,
        action: Optional[str] = None,
        status: str = "recorded",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        safe_metadata = cls._redact(metadata or {})
        event = AuditEvent(
            event_id=str(uuid4()),
            event_type=event_type,
            actor=actor,
            incident_id=incident_id,
            action=action,
            status=status,
            metadata=safe_metadata,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        cls._events.append(event)

        # Audit is the common cross-cutting path for the governed workflow. Mirror
        # each audit event into the dual text/JSON operational timeline so an
        # operator can reconstruct what happened without querying the audit DB.
        log_workflow_step(
            incident_id=incident_id,
            stage=cls._timeline_stage(event_type),
            component=cls._timeline_component(event_type, actor),
            action=event_type,
            status=cls._timeline_status(event_type, status),
            summary=str(event_type).replace("_", " "),
            details={
                "audit_event_id": event.event_id,
                "actor": actor,
                "requested_action": action,
                **safe_metadata,
            },
        )
        return event

    @classmethod
    def list_events(cls, incident_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        events = cls._events
        if incident_id:
            events = [e for e in events if e.incident_id == incident_id]
        return [asdict(e) for e in events[-max(1, limit):]]

    @classmethod
    async def flush_to_store(cls, store: Any, incident_id: Optional[str] = None) -> int:
        pending = cls.list_events(incident_id=incident_id, limit=max(len(cls._events), 1))
        for event in pending:
            await store.append(event)
        if incident_id:
            cls._events = [e for e in cls._events if e.incident_id != incident_id]
        else:
            cls._events.clear()
        return len(pending)

    @classmethod
    def clear(cls) -> None:
        cls._events.clear()
