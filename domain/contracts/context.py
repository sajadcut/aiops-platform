import contextvars
from uuid import uuid4

# contextvar برای نگهداری trace_id در طول یک درخواست
_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")

def set_trace_id(trace_id: str) -> None:
    """تنظیم trace_id برای درخواست جاری"""
    _trace_id.set(trace_id)

def get_trace_id() -> str:
    """دریافت trace_id درخواست جاری"""
    return _trace_id.get()

def generate_trace_id() -> str:
    """تولید یک trace_id جدید"""
    return f"trc_{uuid4().hex[:12]}"