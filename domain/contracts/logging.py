import structlog
import logging
from domain.contracts.config import settings

def configure_logging():
    """پیکربندی structlog برای لاگینگ ساختاریافته"""
    
    # تنظیم سطح لاگ
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    # پیکربندی structlog
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # تنظیم handler برای خروجی کنسول
    handler = logging.StreamHandler()
    
    if settings.LOG_JSON:
        # خروجی JSON برای محیط‌های تولید
        formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer()
        )
    else:
        # خروجی خوانا برای توسعه
        formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer()
        )
    
    handler.setFormatter(formatter)
    
    # گرفتن logger اصلی و اضافه کردن handler
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)
    
    # جلوگیری از لاگ‌های تکراری
    root_logger.propagate = False

# ایجاد logger پیش‌فرض
logger = structlog.get_logger()