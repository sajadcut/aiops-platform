# ============================================================
# FILE: app/services/incident_memory_service.py
# ============================================================

from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.operational_memory import (
    OperationalMemoryService,
)


class IncidentMemoryService:

    @classmethod
    async def save_verified_incident(
        cls,
        db: AsyncSession,
        incident_id: Optional[UUID],
        service: str,
        pattern: str,
        symptoms: Dict[str, Any],
        root_cause: Optional[str],
        action: Optional[str],
        verification_status: str,
        outcome: Optional[str],
        environment: Optional[str] = None,
    ):

        if verification_status in {
            "inconclusive",
        }:
            return None

        memory = OperationalMemoryService(
            db
        )

        return await memory.add_entry(
            pattern=pattern,
            symptoms=symptoms,
            root_cause=root_cause,
            action=action,
            verification_result=verification_status,
            outcome=outcome,
            environment=environment,
            service_scope=service,
            incident_id=incident_id,
        )