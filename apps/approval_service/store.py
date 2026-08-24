"""Approval persistence abstraction.

The current repository remains compatible with the existing in-memory
ApprovalService while exposing a storage contract for the PostgreSQL-backed
implementation planned for the next persistence phase.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class ApprovalStore(ABC):
    @abstractmethod
    def create(self, record: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def get(self, approval_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def update(self, approval_id: str, values: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class InMemoryApprovalStore(ApprovalStore):
    def __init__(self) -> None:
        self._items: Dict[str, Dict[str, Any]] = {}

    def create(self, record: Dict[str, Any]) -> Dict[str, Any]:
        self._items[str(record["approval_id"])] = dict(record)
        return dict(self._items[str(record["approval_id"])])

    def get(self, approval_id: str) -> Optional[Dict[str, Any]]:
        record = self._items.get(approval_id)
        return dict(record) if record else None

    def update(self, approval_id: str, values: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        record = self._items.get(approval_id)
        if record is None:
            return None
        record.update(values)
        return dict(record)

    def clear(self) -> None:
        self._items.clear()
