import asyncio
from typing import TypeVar, Callable, Any, Optional
from functools import wraps
from app.core.logging import logger

T = TypeVar('T')

class RetryError(Exception):
    """خطای مربوط به تلاش مجدد"""
    pass

async def retry_async(
    func: Callable[..., Any],
    *args,
    max_retries: int = 3,
    delay_seconds: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,),
    **kwargs
) -> Any:
    """
    اجرای تابع با قابلیت تلاش مجدد.
    
    Args:
        func: تابع async برای اجرا
        max_retries: حداکثر تعداد تلاش
        delay_seconds: تأخیر اولیه
        backoff_factor: ضریب افزایش تأخیر
        exceptions: استثناهایی که باعث تلاش مجدد می‌شوند
    """
    last_exception = None
    current_delay = delay_seconds
    
    for attempt in range(1, max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except exceptions as e:
            last_exception = e
            if attempt < max_retries:
                logger.warning(
                    f"Retry {attempt}/{max_retries} for {func.__name__} after error: {str(e)}. Waiting {current_delay:.2f}s"
                )
                await asyncio.sleep(current_delay)
                current_delay *= backoff_factor
            else:
                logger.error(f"All {max_retries} retries failed for {func.__name__}: {str(e)}")
    
    raise RetryError(f"Function {func.__name__} failed after {max_retries} attempts") from last_exception

def with_retry(max_retries: int = 3, delay_seconds: float = 1.0, backoff_factor: float = 2.0):
    """
    Decorator برای اضافه کردن قابلیت Retry به توابع async.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_async(
                func,
                *args,
                max_retries=max_retries,
                delay_seconds=delay_seconds,
                backoff_factor=backoff_factor,
                **kwargs
            )
        return wrapper
    return decorator