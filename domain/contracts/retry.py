import asyncio
from typing import TypeVar, Callable, Any, Optional
from functools import wraps

from domain.contracts.config import settings
from domain.contracts.logging import logger

T = TypeVar("T")


class RetryError(Exception):
    pass


async def retry_async(
    func: Callable[..., Any],
    *args,
    max_retries: Optional[int] = None,
    delay_seconds: Optional[float] = None,
    backoff_factor: Optional[float] = None,
    exceptions: tuple = (Exception,),
    **kwargs,
) -> Any:
    resolved_max_retries = settings.RETRY_MAX_ATTEMPTS if max_retries is None else max_retries
    resolved_delay = settings.RETRY_DELAY_SECONDS if delay_seconds is None else delay_seconds
    resolved_backoff = settings.RETRY_BACKOFF_FACTOR if backoff_factor is None else backoff_factor

    last_exception = None
    current_delay = resolved_delay

    for attempt in range(1, resolved_max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except exceptions as exc:
            last_exception = exc
            if attempt < resolved_max_retries:
                logger.warning(
                    f"Retry {attempt}/{resolved_max_retries} for {func.__name__} after error: "
                    f"{str(exc)}. Waiting {current_delay:.2f}s"
                )
                await asyncio.sleep(current_delay)
                current_delay *= resolved_backoff
            else:
                logger.error(
                    f"All {resolved_max_retries} retries failed for {func.__name__}: {str(exc)}"
                )

    raise RetryError(
        f"Function {func.__name__} failed after {resolved_max_retries} attempts"
    ) from last_exception


def with_retry(
    max_retries: Optional[int] = None,
    delay_seconds: Optional[float] = None,
    backoff_factor: Optional[float] = None,
):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_async(
                func,
                *args,
                max_retries=max_retries,
                delay_seconds=delay_seconds,
                backoff_factor=backoff_factor,
                **kwargs,
            )

        return wrapper

    return decorator
