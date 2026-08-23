from typing import Dict, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from fastapi import Request, HTTPException, status
from domain.contracts.logging import logger

# ذخیره‌سازی درخواست‌ها در حافظه (در Production با Redis جایگزین شود)
_request_cache: Dict[str, list] = defaultdict(list)

class RateLimiter:
    """
    محدودکننده نرخ درخواست‌ها.
    در MVP از حافظه استفاده می‌کند، در Production باید با Redis جایگزین شود.
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
    
    async def __call__(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        key = f"{client_ip}:{request.url.path}"
        
        # پاکسازی درخواست‌های قدیمی
        now = datetime.now()
        _request_cache[key] = [
            ts for ts in _request_cache.get(key, [])
            if now - ts < timedelta(seconds=self.window_seconds)
        ]
        
        # بررسی محدودیت
        if len(_request_cache[key]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for {client_ip} on {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {self.max_requests} requests per {self.window_seconds} seconds."
            )
        
        # ثبت درخواست جدید
        _request_cache[key].append(now)
    
    @staticmethod
    def clear_cache():
        """پاکسازی کش (برای تست)"""
        _request_cache.clear()

# نمونه‌های پیش‌فرض
rate_limiter_default = RateLimiter(max_requests=100, window_seconds=60)
rate_limiter_strict = RateLimiter(max_requests=20, window_seconds=60)
rate_limiter_loose = RateLimiter(max_requests=500, window_seconds=60)