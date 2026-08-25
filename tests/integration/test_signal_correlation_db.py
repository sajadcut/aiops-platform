from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete

from apps.incident_service.repository import IncidentRepository
from database import AsyncSessionLocal
from domain.models import Incident


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DB_CORRELATION_TEST") != "1",
    reason="requires PostgreSQL acceptance environment",
)


@pytest.mark.asyncio
async def test_postgresql_correlation_lock_and_bounded_lookup():
    incident_id = str(uuid4())
    fingerprint = "test:v1:service-error-payment"
    service = "correlation-ci-payment"
    async with AsyncSessionLocal() as session:
        repo = IncidentRepository(session)
        await repo.acquire_correlation_lock(f"event:prometheus:ci-{incident_id}")
        await repo.acquire_correlation_lock(f"correlation:{fingerprint}")
        await repo.upsert_incident(
            incident_id=incident_id,
            source="elasticsearch",
            service=service,
            severity="high",
            summary="CI correlation acceptance",
            status="analyzing",
            context={"correlation": {"fingerprint": fingerprint}},
        )
        await repo.commit()

        found = await repo.find_correlated_open_incident(
            fingerprint=fingerprint,
            service=service,
            since=datetime.now(timezone.utc) - timedelta(minutes=5),
            limit=5,
        )
        assert found == incident_id

        expired = await repo.find_correlated_open_incident(
            fingerprint=fingerprint,
            service=service,
            since=datetime.now(timezone.utc) + timedelta(minutes=1),
            limit=5,
        )
        assert expired is None

        await session.execute(delete(Incident).where(Incident.id == incident_id))
        await session.commit()
