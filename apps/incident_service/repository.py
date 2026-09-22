from __future__ import annotations

from datetime import date, datetime, time, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, Iterable, Optional
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from domain.models import Evidence, EvidenceType, Finding, Incident, IncidentStatus


def _json_safe(value: Any) -> Any:
    """Convert durable JSON payloads to PostgreSQL/SQLAlchemy-safe primitives.

    Operational context can legitimately contain datetime/UUID/Enum values from
    normalized signals and workflow state. Normalize them at the persistence
    boundary so a successful incident analysis never fails during the final
    database flush with a JSON serialization error.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _json_safe(value.value)
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _json_safe(model_dump(mode="json"))
    raise TypeError(f"unsupported_json_value:{type(value).__name__}")


class IncidentRepository:
    """Canonical PostgreSQL repository for Incident, Evidence and Finding."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert_incident(
        self,
        incident_id: str,
        source: str,
        service: str,
        severity: str | None,
        summary: str | None,
        status: str = "open",
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        incident_uuid = UUID(str(incident_id))
        incident = await self.session.get(Incident, incident_uuid)
        normalized_status = IncidentStatus(status.lower())
        safe_context = _json_safe(context) if context is not None else None
        if incident is None:
            incident = Incident(
                id=incident_uuid,
                source=source,
                severity=severity or "unknown",
                service=service,
                status=normalized_status,
                summary=summary,
                context=safe_context,
            )
            self.session.add(incident)
        else:
            # A source Recovery can race a long-running analysis. Never let a
            # stale workflow result overwrite an already-recorded authoritative
            # recovery and move the incident back to analyzing/open.
            existing_context = dict(incident.context or {})
            recovery_marker = dict(existing_context.get("source_recovery") or {})
            incoming_context = dict(safe_context or {}) if safe_context is not None else None
            if recovery_marker:
                if incoming_context is None:
                    incoming_context = existing_context
                else:
                    incoming_context["source_recovery"] = recovery_marker
                    if existing_context.get("source_recoveries"):
                        incoming_context["source_recoveries"] = existing_context.get("source_recoveries")
                if bool(recovery_marker.get("incident_resolved")) and incident.status != IncidentStatus.CLOSED:
                    normalized_status = IncidentStatus.RESOLVED

            incident.source = source
            incident.severity = severity or incident.severity or "unknown"
            incident.service = service
            incident.status = normalized_status
            incident.summary = summary
            if incoming_context is not None:
                incident.context = incoming_context

    async def set_status(self, incident_id: str, status: str) -> None:
        incident = await self.session.get(Incident, UUID(str(incident_id)))
        if incident is not None:
            incident.status = IncidentStatus(str(status).lower())

    async def record_operational_outcome(
        self,
        incident_id: str,
        *,
        source: str,
        action: str,
        target: str,
        approval_id: Optional[str],
        execution_success: Optional[bool],
        verified: bool,
        verification: Optional[Dict[str, Any]] = None,
        memory_id: Optional[str] = None,
    ) -> Optional[str]:
        """Persist the governed execution outcome into incident state.

        Verified recovery is the only execution-driven path to RESOLVED.
        Failed/inconclusive outcomes escalate unless an authoritative source
        recovery has already resolved the incident. The append-only bounded
        context trail keeps direct/runbook/remediation paths explainable.
        """
        incident = await self.session.get(Incident, UUID(str(incident_id)))
        if incident is None:
            return None

        context = dict(incident.context or {})
        recovery_marker = dict(context.get("source_recovery") or {})
        source_resolved = bool(recovery_marker.get("incident_resolved"))

        if source_resolved and incident.status != IncidentStatus.CLOSED:
            next_status = IncidentStatus.RESOLVED
        elif verified:
            next_status = IncidentStatus.RESOLVED
        else:
            next_status = IncidentStatus.ESCALATED

        outcomes = list(context.get("operational_outcomes") or [])
        outcome = _json_safe(
            {
                "source": str(source or "governed_execution"),
                "action": str(action or ""),
                "target": str(target or ""),
                "approval_id": str(approval_id) if approval_id else None,
                "execution_success": (
                    None
                    if execution_success is None
                    else bool(execution_success)
                ),
                "verified": bool(verified),
                "verification": dict(verification or {}),
                "memory_id": str(memory_id) if memory_id else None,
                "recorded_at": datetime.now(timezone.utc),
            }
        )

        identity = (
            outcome.get("source"),
            outcome.get("approval_id"),
            outcome.get("action"),
            outcome.get("target"),
            outcome.get("verified"),
            str((outcome.get("verification") or {}).get("status") or ""),
        )
        existing_index = None
        for index, item in enumerate(outcomes):
            if not isinstance(item, dict):
                continue
            item_identity = (
                item.get("source"),
                item.get("approval_id"),
                item.get("action"),
                item.get("target"),
                item.get("verified"),
                str((item.get("verification") or {}).get("status") or ""),
            )
            if item_identity == identity:
                existing_index = index
                break
        if existing_index is None:
            outcomes.append(outcome)
        else:
            outcomes[existing_index] = outcome

        context["operational_outcomes"] = outcomes[-50:]
        context["latest_operational_outcome"] = outcome
        incident.context = _json_safe(context)
        incident.status = next_status
        return str(
            incident.status.value
            if isinstance(incident.status, IncidentStatus)
            else incident.status
        )

    async def acquire_correlation_lock(self, fingerprint: str) -> None:
        """Serialize creation for a deterministic correlation fingerprint."""
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:fingerprint, 0))"),
            {"fingerprint": str(fingerprint)},
        )

    async def find_correlated_open_incident(
        self,
        *,
        fingerprint: str,
        service: str,
        since: datetime,
        limit: int = 25,
    ) -> Optional[str]:
        """Find a bounded open/analyzing incident with the same fingerprint."""
        rows = (
            await self.session.execute(
                select(Incident)
                .where(
                    Incident.service == str(service),
                    Incident.started_at >= since,
                    Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.ANALYZING]),
                )
                .order_by(Incident.started_at.desc())
                .limit(max(1, min(int(limit), 100)))
            )
        ).scalars().all()
        for incident in rows:
            context = dict(incident.context or {})
            correlation = dict(context.get("correlation") or {})
            if str(correlation.get("fingerprint") or "") == str(fingerprint):
                return str(incident.id)
        return None

    async def attach_correlated_signal(
        self,
        incident_id: str,
        *,
        evidence: Dict[str, Any],
        signal_metadata: Dict[str, Any],
    ) -> None:
        """Attach a related trigger without rewriting the incident's primary source."""
        incident = await self.session.get(Incident, UUID(str(incident_id)))
        if incident is None:
            raise ValueError("correlated_incident_not_found")
        await self.add_evidence(incident_id, [evidence])
        context = dict(incident.context or {})
        related = list(context.get("related_signals") or [])
        identity = (str(signal_metadata.get("source") or ""), str(signal_metadata.get("source_id") or ""))
        if identity not in {
            (str(item.get("source") or ""), str(item.get("source_id") or ""))
            for item in related if isinstance(item, dict)
        }:
            related.append(_json_safe(dict(signal_metadata)))
        context["related_signals"] = related[-100:]
        incident.context = _json_safe(context)

    async def find_incident_by_evidence_reference(
        self,
        *,
        source: str,
        reference: str,
    ) -> Optional[str]:
        """Return the incident already owning a source event/reference.

        This is the fail-safe idempotency key for webhook retries. Cross-source
        correlation is deliberately not inferred here; only the exact source +
        source event identity is deduplicated.
        """
        incident_id = (
            await self.session.execute(
                select(Evidence.incident_id)
                .where(
                    Evidence.source == str(source),
                    Evidence.reference == str(reference),
                )
                .order_by(Evidence.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        return str(incident_id) if incident_id is not None else None

    async def add_findings(self, incident_id: str, findings: Iterable[Dict[str, Any]]) -> None:
        incident_uuid = UUID(str(incident_id))
        for finding in findings:
            statement = finding.get("statement") or finding.get("description") or finding.get("summary")
            if not statement:
                continue
            agent = str(finding.get("agent_name") or finding.get("agent") or "unknown")
            finding_type = str(finding.get("finding_type") or "analysis")
            existing = (
                await self.session.execute(
                    select(Finding.id).where(
                        Finding.incident_id == incident_uuid,
                        Finding.agent == agent,
                        Finding.finding_type == finding_type,
                        Finding.statement == str(statement),
                    ).limit(1)
                )
            ).scalar_one_or_none()
            if existing:
                continue
            self.session.add(
                Finding(
                    id=uuid4(),
                    incident_id=incident_uuid,
                    agent=agent,
                    finding_type=finding_type,
                    statement=str(statement),
                    evidence_ids=_json_safe(list(finding.get("evidence_ids") or [])),
                    confidence=float(finding.get("confidence") or 0.0),
                )
            )

    @staticmethod
    def _evidence_type(value: Any) -> EvidenceType:
        normalized = str(value or "event").lower()
        try:
            return EvidenceType(normalized)
        except ValueError:
            return EvidenceType.EVENT

    async def add_evidence(self, incident_id: str, evidence: Iterable[Dict[str, Any]]) -> None:
        incident_uuid = UUID(str(incident_id))
        for item in evidence:
            reference = item.get("reference") or item.get("evidence_id")
            if reference:
                existing = (
                    await self.session.execute(
                        select(Evidence.id).where(
                            Evidence.incident_id == incident_uuid,
                            Evidence.reference == str(reference),
                        )
                    )
                ).scalar_one_or_none()
                if existing:
                    continue
            raw_confidence = item.get("confidence")
            confidence = 1.0 if raw_confidence is None else float(raw_confidence)
            self.session.add(
                Evidence(
                    id=uuid4(),
                    incident_id=incident_uuid,
                    type=self._evidence_type(item.get("type")),
                    source=str(item.get("source") or "unknown"),
                    query=item.get("query"),
                    time_range=_json_safe(item.get("time_range")),
                    reference=str(reference) if reference else None,
                    raw_data=_json_safe(item.get("raw_data") or item),
                    confidence=confidence,
                )
            )

    async def commit(self) -> None:
        await self.session.commit()
