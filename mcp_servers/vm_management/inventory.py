from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Dict, List

import yaml
from pydantic import BaseModel, Field, field_validator

_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_ALLOWED_OPERATIONS = {
    "collect_vm_metrics",
    "service_status",
    "process_snapshot",
    "restart_service",
    "service_logs",
    "validate_service_config",
    "reload_service",
    "reboot_vm",
    "disk_usage",
    "network_status",
}


class VMRecord(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    ip: str
    environment: str = Field(min_length=1, max_length=64)
    role: str = Field(min_length=1, max_length=128)
    ssh_user: str = Field(min_length=1, max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    credential_ref: str = Field(min_length=1, max_length=128)
    allowed_operations: List[str] = Field(default_factory=list)
    allowed_services: List[str] = Field(default_factory=list)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))

    @field_validator("allowed_operations")
    @classmethod
    def validate_operations(cls, value: List[str]) -> List[str]:
        normalized = list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
        unknown = sorted(set(normalized) - _ALLOWED_OPERATIONS)
        if unknown:
            raise ValueError(f"unknown_allowed_operations:{','.join(unknown)}")
        return normalized

    @field_validator("allowed_services")
    @classmethod
    def validate_services(cls, value: List[str]) -> List[str]:
        normalized = list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
        if any(not _SERVICE_RE.fullmatch(item) for item in normalized):
            raise ValueError("invalid_service_name")
        return normalized


class VMInventory:
    def __init__(self, records: List[VMRecord]):
        self._by_id: Dict[str, VMRecord] = {}
        self._by_host: Dict[str, VMRecord] = {}
        for record in records:
            aliases = {record.id, record.hostname, record.ip}
            if any(alias in self._by_host for alias in aliases):
                raise ValueError(f"duplicate_vm_target:{record.id}")
            self._by_id[record.id] = record
            for alias in aliases:
                self._by_host[alias] = record

    @classmethod
    def load(cls, path: str) -> "VMInventory":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        records = [VMRecord.model_validate(item) for item in raw.get("vms", [])]
        if not records:
            raise ValueError("vm_inventory_empty")
        return cls(records)

    def resolve(self, target: str) -> VMRecord:
        try:
            return self._by_host[str(target).strip()]
        except KeyError as exc:
            raise PermissionError("vm_target_not_authorized") from exc

    def authorize(self, target: str, operation: str, service: str | None = None) -> VMRecord:
        record = self.resolve(target)
        if operation not in record.allowed_operations:
            raise PermissionError("vm_operation_not_authorized")
        if service is not None:
            if not _SERVICE_RE.fullmatch(service) or service not in record.allowed_services:
                raise PermissionError("vm_service_not_authorized")
        return record
