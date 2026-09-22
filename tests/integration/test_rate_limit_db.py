import asyncio
import os
from hashlib import sha256
from uuid import uuid4

import pytest
from sqlalchemy import text

from database import AsyncSessionLocal
from domain.contracts.rate_limit import RateLimiter


pytestmark = [
    pytest.mark.skipif(
        os.getenv("RUN_DB_RATE_LIMIT_TEST") != "1",
        reason="requires PostgreSQL distributed rate-limit acceptance environment",
    ),
    pytest.mark.asyncio(loop_scope="module"),
]


@pytest.mark.asyncio(loop_scope="module")
async def test_postgres_rate_limit_is_atomic_across_concurrent_callers():
    rate_key = sha256(f"ci-rate-limit-{uuid4()}".encode()).hexdigest()
    limiter = RateLimiter(
        max_requests=2,
        window_seconds=60,
        backend="postgres",
    )

    first, second, third = await asyncio.gather(
        limiter._consume_postgres(rate_key),
        limiter._consume_postgres(rate_key),
        limiter._consume_postgres(rate_key),
    )

    assert sum(bool(value) for value in (first, second, third)) == 2

    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                text(
                    "SELECT request_count FROM api_rate_limits "
                    "WHERE rate_key=:rate_key"
                ),
                {"rate_key": rate_key},
            )
        ).first()
        assert row is not None
        assert int(row[0]) == 2
        await db.execute(
            text("DELETE FROM api_rate_limits WHERE rate_key=:rate_key"),
            {"rate_key": rate_key},
        )
        await db.commit()


@pytest.mark.asyncio(loop_scope="module")
async def test_postgres_rate_limit_resets_after_window_expiry():
    rate_key = sha256(f"ci-rate-reset-{uuid4()}".encode()).hexdigest()
    limiter = RateLimiter(
        max_requests=1,
        window_seconds=60,
        backend="postgres",
    )

    assert await limiter._consume_postgres(rate_key) is True
    assert await limiter._consume_postgres(rate_key) is False

    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                "UPDATE api_rate_limits "
                "SET window_started_at=NOW() - INTERVAL '120 seconds' "
                "WHERE rate_key=:rate_key"
            ),
            {"rate_key": rate_key},
        )
        await db.commit()

    assert await limiter._consume_postgres(rate_key) is True

    async with AsyncSessionLocal() as db:
        await db.execute(
            text("DELETE FROM api_rate_limits WHERE rate_key=:rate_key"),
            {"rate_key": rate_key},
        )
        await db.commit()
