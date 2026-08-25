from typing import Dict
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import Request, HTTPException, status

from domain.contracts.config import settings
from domain.contracts.logging import logger


_request_cache: Dict[str, list] = defaultdict(list)


class RateLimiter:
    """In-process rate limiter using centrally configured limits.

    The storage backend is intentionally in-process for the current repository
    scope; production deployment may replace storage without changing the
    environment contract.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def __call__(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        key = f"{client_ip}:{request.url.path}"
        now = datetime.now()
        _request_cache[key] = [
            ts
            for ts in _request_cache.get(key, [])
            if now - ts < timedelta(seconds=self.window_seconds)
        ]
        if len(_request_cache[key]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for {client_ip} on {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "Rate limit exceeded. Maximum "
                    f"{self.max_requests} requests per {self.window_seconds} seconds."
                ),
            )
        _request_cache[key].append(now)

    @staticmethod
    def clear_cache():
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
