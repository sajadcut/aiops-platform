from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class IncidentRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert_incident(self, incident_id: str, source: str, service: str, severity: str | None, summary: str | None, status: str = "open") -> None:
        now = datetime.now(timezone.utc)
        await self.session.execute(
            text(
                """
                INSERT INTO incidents (incident_id, source, severity, service, status, summary, started_at, created_at, updated_at)
                VALUES (:id, :source, :severity, :service, :status, :summary, :started_at, :created_at, :updated_at)
                ON CONFLICT (incident_id) DO UPDATE SET severity=EXCLUDED.severity, service=EXCLUDED.service,
                    status=EXCLUDED.status, summary=EXCLUDED.summary, updated_at=EXCLUDED.updated_at
                """
            ),
            {"id": incident_id, "source": source, "severity": severity, "service": service, "status": status,
             "summary": summary, "started_at": now, "created_at": now, "updated_at": now},
        )

    async def add_findings(self, incident_id: str, findings: Iterable[Dict[str, Any]]) -> None:
        for finding in findings:
            await self.session.execute(
                text(
                    """
                    INSERT INTO incident_findings (incident_id, agent, finding_type, statement, evidence_ids, confidence)
                    VALUES (:incident_id, :agent, :finding_type, :statement, CAST(:evidence_ids AS jsonb), :confidence)
                    """
                ),
                {
                    "incident_id": incident_id,
                    "agent": finding.get("agent"),
                    "finding_type": finding.get("finding_type"),
                    "statement": finding.get("statement") or finding.get("description"),
                    "evidence_ids": json.dumps(finding.get("evidence_ids") or []),
                    "confidence": finding.get("confidence"),
                },
            )

    async def add_evidence(self, incident_id: str, evidence: Iterable[Dict[str, Any]]) -> None:
        for item in evidence:
            evidence_id = str(item.get("evidence_id") or item.get("reference") or f"{item.get('source','unknown')}:{item.get('type','unknown')}:{hash(json.dumps(item, sort_keys=True, default=str))}")
            await self.session.execute(
                text(
                    """
                    INSERT INTO incident_evidence (evidence_id, incident_id, evidence_type, source, reference, payload)
                    VALUES (:evidence_id, :incident_id, :evidence_type, :source, :reference, CAST(:payload AS jsonb))
                    ON CONFLICT (evidence_id) DO NOTHING
                    """
                ),
                {"evidence_id": evidence_id, "incident_id": incident_id, "evidence_type": item.get("type", "unknown"),
                 "source": item.get("source", "unknown"), "reference": item.get("reference"),
                 "payload": json.dumps(item.get("raw_data") or item, default=str)},
            )

    async def commit(self) -> None:
        await self.session.commit()
