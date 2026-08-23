# ============================================================
# FILE: app/services/approval_service.py
# ============================================================

from datetime import datetime, timezone
from typing import Dict, Optional
from uuid import uuid4


class ApprovalService:

    _approvals: Dict[str, Dict] = {}

    @classmethod
    def create_request(
        cls,
        incident_id: str,
        action: str,
        risk_level: str,
        approver: str,
    ) -> Dict:

        approval_id = str(uuid4())

        record = {
            "approval_id": approval_id,
            "incident_id": incident_id,
            "action": action,
            "risk_level": risk_level,
            "approver": approver,
            "status": "pending",
            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "approved_at": None,
            "rejected_at": None,
        }

        cls._approvals[approval_id] = record

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