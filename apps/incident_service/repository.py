from __future__ import annotations

from typing import Any, Dict, Iterable
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.models import Evidence, EvidenceType, Finding, Incident, IncidentStatus


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
    ) -> None:
        incident_uuid = UUID(str(incident_id))
        incident = await self.session.get(Incident, incident_uuid)
        normalized_status = IncidentStatus(status.lower())
        if incident is None:
            incident = Incident(
                id=incident_uuid,
                source=source,
                severity=severity or "unknown",
                service=service,
                status=normalized_status,
                summary=summary,
            )
            self.session.add(incident)
        else:
            incident.source = source
            incident.severity = severity or incident.severity or "unknown"
            incident.service = service
            incident.status = normalized_status
            incident.summary = summary

    async def add_findings(self, incident_id: str, findings: Iterable[Dict[str, Any]]) -> None:
        incident_uuid = UUID(str(incident_id))
        for finding in findings:
            statement = finding.get("statement") or finding.get("description") or finding.get("summary")
            if not statement:
                continue
            self.session.add(
                Finding(
                    id=uuid4(),
                    incident_id=incident_uuid,
                    agent=str(finding.get("agent") or "unknown"),
                    finding_type=str(finding.get("finding_type") or "analysis"),
                    statement=str(statement),
                    evidence_ids=list(finding.get("evidence_ids") or []),
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
            self.session.add(
                Evidence(
                    id=uuid4(),
                    incident_id=incident_uuid,
                    type=self._evidence_type(item.get("type")),
                    source=str(item.get("source") or "unknown"),
                    query=item.get("query"),
                    time_range=item.get("time_range"),
                    reference=str(reference) if reference else None,
                    raw_data=item.get("raw_data") or item,
                    confidence=float(item.get("confidence") or 1.0),
                )
            )

    async def commit(self) -> None:
        await self.session.commit()
