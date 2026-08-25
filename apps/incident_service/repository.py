from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class IncidentRepository:
    """Durable repository for the canonical incidents/evidences/findings schema."""

    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def _evidence_uuid(item: Dict[str, Any]) -> uuid.UUID:
        stable = str(
            item.get("evidence_id")
            or item.get("reference")
            or f"{item.get('source', 'unknown')}:{item.get('type', 'unknown')}:{json.dumps(item, sort_keys=True, default=str)}"
        )
        return uuid.uuid5(uuid.NAMESPACE_URL, f"aiops:evidence:{stable}")

    async def upsert_incident(
        self,
        incident_id: str,
        source: str,
        service: str,
        severity: str | None,
        summary: str | None,
        status: str = "open",
        context: Dict[str, Any] | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        await self.session.execute(
            text(
                """
                INSERT INTO incidents (id, source, severity, service, status, summary, context, started_at, created_at, updated_at)
                VALUES (:id, :source, :severity, :service, :status, :summary, CAST(:context AS jsonb), :started_at, :created_at, :updated_at)
                ON CONFLICT (id) DO UPDATE SET
                    severity=EXCLUDED.severity,
                    service=EXCLUDED.service,
                    status=EXCLUDED.status,
                    summary=EXCLUDED.summary,
                    context=COALESCE(EXCLUDED.context, incidents.context),
                    updated_at=EXCLUDED.updated_at
                """
            ),
            {
                "id": incident_id,
                "source": source,
                "severity": severity,
                "service": service,
                "status": status,
                "summary": summary,
                "context": json.dumps(context or {}),
                "started_at": now,
                "created_at": now,
                "updated_at": now,
            },
        )

    async def add_findings(self, incident_id: str, findings: Iterable[Dict[str, Any]]) -> None:
        for finding in findings:
            finding_id = uuid.uuid4()
            await self.session.execute(
                text(
                    """
                    INSERT INTO findings (id, incident_id, agent, finding_type, statement, evidence_ids, confidence)
                    VALUES (:id, :incident_id, :agent, :finding_type, :statement, CAST(:evidence_ids AS jsonb), :confidence)
                    """
                ),
                {
                    "id": finding_id,
                    "incident_id": incident_id,
                    "agent": finding.get("agent") or finding.get("agent_name") or "unknown",
                    "finding_type": finding.get("finding_type") or "finding",
                    "statement": finding.get("statement") or finding.get("description") or "Unspecified finding",
                    "evidence_ids": json.dumps(finding.get("evidence_ids") or []),
                    "confidence": float(finding.get("confidence") or 0.0),
                },
            )

    async def add_evidence(self, incident_id: str, evidence: Iterable[Dict[str, Any]]) -> None:
        for item in evidence:
            evidence_id = self._evidence_uuid(item)
            raw_data = item.get("raw_data") or item
            await self.session.execute(
                text(
                    """
                    INSERT INTO evidences
                        (id, incident_id, type, source, query, time_range, reference, raw_data, confidence)
                    VALUES
                        (:id, :incident_id, :type, :source, :query, CAST(:time_range AS jsonb), :reference,
                         CAST(:raw_data AS jsonb), :confidence)
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {
                    "id": evidence_id,
                    "incident_id": incident_id,
                    "type": str(item.get("type", "event")).lower(),
                    "source": str(item.get("source", "unknown")),
                    "query": item.get("query"),
                    "time_range": json.dumps(item.get("time_range")) if item.get("time_range") is not None else None,
                    "reference": item.get("reference"),
                    "raw_data": json.dumps(raw_data, default=str),
                    "confidence": float(item.get("confidence", 1.0)),
                },
            )

    async def set_status(self, incident_id: str, status: str) -> None:
        await self.session.execute(
            text("UPDATE incidents SET status=:status, updated_at=CURRENT_TIMESTAMP WHERE id=:id"),
            {"status": status, "id": incident_id},
        )

    async def commit(self) -> None:
        await self.session.commit()