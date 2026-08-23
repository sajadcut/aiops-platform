from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
from pydantic import BaseModel

class Alert(BaseModel):
    """مدل استاندارد Alert برای کل سیستم"""
    source: str  # zabbix, prometheus, etc.
    source_id: str  # شناسه اصلی در منبع
    severity: str  # critical, high, medium, low
    service: Optional[str] = None
    message: str
    timestamp: datetime
    raw_data: Dict[str, Any] = {}

class LogEntry(BaseModel):
    """مدل استاندارد Log برای کل سیستم"""
    timestamp: datetime
    service: Optional[str] = None
    level: str  # error, warning, info, debug
    message: str
    source: str  # elasticsearch, filebeat, etc.
    raw_data: Dict[str, Any] = {}

class MetricPoint(BaseModel):
    """مدل استاندارد Metric برای کل سیستم"""
    timestamp: datetime
    service: Optional[str] = None
    name: str  # cpu_usage, memory_usage, error_rate, etc.
    value: float
    labels: Dict[str, str] = {}
    source: str  # prometheus, zabbix, etc.

class BaseConnector(ABC):
    """کلاس پایه برای همه Connectorها"""
    
    @property
    @abstractmethod
    def source_name(self) -> str:
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """بررسی در دسترس بودن منبع داده"""
        pass
    
    @abstractmethod
    async def get_alerts(
        self,
        since: Optional[datetime] = None,
        service: Optional[str] = None,
        limit: int = 100
    ) -> List[Alert]:
        """دریافت Alertها از منبع (با فیلترهای اختیاری)"""
        pass
    
    @abstractmethod
    async def get_logs(
        self,
        service: str,
        since: datetime,
        until: Optional[datetime] = None,
        level: Optional[str] = None,
        limit: int = 100
    ) -> List[LogEntry]:
        """دریافت لاگ‌های یک سرویس در بازه زمانی مشخص"""
        pass
    
    @abstractmethod
    async def get_metrics(
        self,
        service: str,
        metric_names: List[str],
        since: datetime,
        until: Optional[datetime] = None
    ) -> List[MetricPoint]:
        """دریافت متریک‌های یک سرویس در بازه زمانی مشخص"""
        pass