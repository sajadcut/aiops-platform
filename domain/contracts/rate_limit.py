from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Dict, Optional

from fastapi import HTTPException, Request, status

from domain.contracts.config import settings
from domain.contracts.logging import logger


_request_cache: Dict[str, list[datetime]] = defaultdict(list)


class RateLimiter:
    """Fixed-window limiter with a shared production backend.

    Development/test stay in-process for speed and isolation. Production uses
    PostgreSQL automatically so all API replicas enforce one shared quota
    without introducing Redis while the message/distributed-technology ADR is
    still open.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        *,
        backend: Optional[str] = None,
    ):
        self.max_requests = int(max_requests)
        self.window_seconds = int(window_seconds)
        self.backend = backend

    def _backend(self) -> str:
        if self.backend:
            return str(self.backend).strip().lower()
        return "postgres" if settings.APP_ENV == "production" else "memory"

    @staticmethod
    def _route_template(request: Request) -> str:
        route = request.scope.get("route")
        pattern = str(getattr(route, "path", "") or "").strip()
        return pattern or request.url.path

    @classmethod
    def _rate_key(cls, request: Request) -> tuple[str, str]:
        client_ip = request.client.host if request.client else "unknown"
        route = cls._route_template(request)
        raw = f"{client_ip}|{request.method.upper()}|{route}"
        return sha256(raw.encode("utf-8")).hexdigest(), route

    async def _consume_postgres(self, rate_key: str) -> bool:
        # Lazy imports prevent the domain-contract module from creating a
        # database/config import cycle during application bootstrap.
        from sqlalchemy import text

        from database import AsyncSessionLocal

        statement = text(
            """
            INSERT INTO api_rate_limits
                (rate_key, window_started_at, request_count, updated_at)
            VALUES
                (:rate_key, NOW(), 1, NOW())
            ON CONFLICT (rate_key) DO UPDATE
            SET
                request_count = CASE
                    WHEN api_rate_limits.window_started_at
                         <= NOW() - (:window_seconds * INTERVAL '1 second')
                    THEN 1
                    ELSE api_rate_limits.request_count + 1
                END,
                window_started_at = CASE
                    WHEN api_rate_limits.window_started_at
                         <= NOW() - (:window_seconds * INTERVAL '1 second')
                    THEN NOW()
                    ELSE api_rate_limits.window_started_at
                END,
                updated_at = NOW()
            WHERE
                api_rate_limits.window_started_at
                    <= NOW() - (:window_seconds * INTERVAL '1 second')
                OR api_rate_limits.request_count < :max_requests
            RETURNING request_count
            """
        )
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                statement,
                {
                    "rate_key": rate_key,
                    "window_seconds": self.window_seconds,
                    "max_requests": self.max_requests,
                },
            )
            allowed = result.first() is not None
            await db.commit()
            return allowed

    def _consume_memory(self, rate_key: str) -> bool:
        now = datetime.now(timezone.utc)
        _request_cache[rate_key] = [
            ts
            for ts in _request_cache.get(rate_key, [])
            if now - ts < timedelta(seconds=self.window_seconds)
        ]
        if len(_request_cache[rate_key]) >= self.max_requests:
            return False
        _request_cache[rate_key].append(now)
        return True

    async def __call__(self, request: Request) -> None:
        rate_key, route = self._rate_key(request)
        backend = self._backend()

        if backend == "postgres":
            try:
                allowed = await self._consume_postgres(rate_key)
            except Exception as exc:
                logger.error(
                    "rate_limit_backend_unavailable",
                    backend="postgres",
                    route=route,
                    error_type=type(exc).__name__,
                )
                # Production rate limiting is a security control. If its shared
                # backend is unavailable, do not silently fall back to per-pod
                # memory and multiply the effective quota.
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Rate limit backend unavailable.",
                ) from exc
        elif backend == "memory":
            allowed = self._consume_memory(rate_key)
        else:
            raise RuntimeError(f"unsupported_rate_limit_backend:{backend}")

        if not allowed:
            logger.warning(
                "rate_limit_exceeded",
                route=route,
                method=request.method.upper(),
                client_key=rate_key[:12],
                max_requests=self.max_requests,
                window_seconds=self.window_seconds,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "Rate limit exceeded. Maximum "
                    f"{self.max_requests} requests per "
                    f"{self.window_seconds} seconds."
                ),
            )

    @staticmethod
    def clear_cache() -> None:
        _request_cache.clear()


rate_limiter_default = RateLimiter(
    max_requests=settings.API_RATE_LIMIT_PER_MINUTE,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
)
rate_limiter_strict = RateLimiter(
    max_requests=settings.RATE_LIMIT_STRICT_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
)
rate_limiter_loose = RateLimiter(
    max_requests=settings.RATE_LIMIT_LOOSE_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
)
