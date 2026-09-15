# ============================================================
# FILE 1: app/services/approval_service.py
# ============================================================

from datetime import datetime, timezone
from typing import Dict, Optional
from uuid import uuid4

from domain.contracts.logging import log_workflow_step


class ApprovalService:
    """
    Human-in-the-loop approval service.

    Current implementation is in-memory for development.
    It will later be replaced by PostgreSQL persistence.
    """

    _approvals: Dict[str, Dict] = {}

    @classmethod
    def create_request(
        cls,
        incident_id: str,
        action: str,
        risk_level: str,
        approver: str,
        metadata: Optional[Dict] = None,
    ) -> Dict:

        approval_id = str(uuid4())

        record = {
            "approval_id": approval_id,
            "incident_id": incident_id,
            "action": action,
            "risk_level": risk_level,
            "approver": approver,
            "status": "pending",
            "metadata": metadata or {},
            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "approved_at": None,
            "rejected_at": None,
        }

        cls._approvals[approval_id] = record
        log_workflow_step(
            incident_id=incident_id,
            stage="approval",
            component="approval_service",
            action="approval_requested",
            status="waiting",
            summary=f"Approval requested for action {action}",
            details={
                "approval_id": approval_id,
                "risk_level": risk_level,
                "approver": approver,
            },
        )

        return record

    @classmethod
    def get(
        cls,
        approval_id: str,
    ) -> Optional[Dict]:

        return cls._approvals.get(
            approval_id
        )

    @classmethod
    def approve(
        cls,
        approval_id: str,
    ) -> Optional[Dict]:

        record = cls.get(approval_id)

        if record is None:
            return None

        if record["status"] != "pending":
            return record

        record["status"] = "approved"
        record["approved_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        log_workflow_step(
            incident_id=str(record.get("incident_id") or "") or None,
            stage="approval",
            component="approval_service",
            action="approval_approved",
            status="completed",
            summary=f"Approval granted for action {record.get('action')}",
            details={
                "approval_id": approval_id,
                "risk_level": record.get("risk_level"),
                "approver": record.get("approver"),
            },
        )

        return record

    @classmethod
    def reject(
        cls,
        approval_id: str,
    ) -> Optional[Dict]:

        record = cls.get(approval_id)

        if record is None:
            return None

        if record["status"] != "pending":
            return record

        record["status"] = "rejected"
        record["rejected_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        log_workflow_step(
            incident_id=str(record.get("incident_id") or "") or None,
            stage="approval",
            component="approval_service",
            action="approval_rejected",
            status="blocked",
            summary=f"Approval rejected for action {record.get('action')}",
            details={
                "approval_id": approval_id,
                "risk_level": record.get("risk_level"),
                "approver": record.get("approver"),
            },
            level="warning",
        )

        return record

    @classmethod
    def is_approved(
        cls,
        approval_id: str,
    ) -> bool:

        record = cls.get(approval_id)

        return bool(
            record
            and record["status"] == "approved"
        )

    @classmethod
    def clear(cls) -> None:
        cls._approvals.clear()