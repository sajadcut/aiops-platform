from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


SESSION_TTL_SECONDS = 24 * 60 * 60
PROPOSAL_TTL_SECONDS = 15 * 60
HISTORY_LIMIT = 40


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))


class ChatStore:
    """Durable PostgreSQL store for chat ownership, history and action proposals."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_session(self, owner_subject: str, owner_roles: Iterable[str]) -> dict[str, Any]:
        session_id = uuid4()
        now = _utcnow()
        expires_at = now + timedelta(seconds=SESSION_TTL_SECONDS)
        row = (
            await self.session.execute(
                text(
                    """
                    INSERT INTO chat_sessions
                    (session_id, owner_subject, owner_roles, created_at, updated_at, expires_at)
                    VALUES (:session_id, :owner_subject, CAST(:owner_roles AS jsonb), :now, :now, :expires_at)
                    RETURNING session_id, owner_subject, owner_roles, created_at, updated_at, expires_at
                    """
                ),
                {
                    "session_id": session_id,
                    "owner_subject": owner_subject,
                    "owner_roles": _json(sorted(set(str(role) for role in owner_roles))),
                    "now": now,
                    "expires_at": expires_at,
                },
            )
        ).mappings().one()
        await self.session.commit()
        return dict(row)

    async def get_session(self, session_id: UUID | str, owner_subject: str) -> Optional[dict[str, Any]]:
        row = (
            await self.session.execute(
                text(
                    """
                    SELECT session_id, owner_subject, owner_roles, created_at, updated_at, expires_at
                    FROM chat_sessions
                    WHERE session_id=:session_id AND owner_subject=:owner_subject
                    """
                ),
                {"session_id": str(session_id), "owner_subject": owner_subject},
            )
        ).mappings().first()
        if not row:
            return None
        record = dict(row)
        expires_at = record.get("expires_at")
        if expires_at is not None and expires_at <= _utcnow():
            await self.session.execute(
                text("DELETE FROM chat_sessions WHERE session_id=:session_id"),
                {"session_id": str(session_id)},
            )
            await self.session.commit()
            return None
        return record

    async def touch_session(self, session_id: UUID | str) -> None:
        now = _utcnow()
        await self.session.execute(
            text(
                "UPDATE chat_sessions SET updated_at=:now, expires_at=:expires_at "
                "WHERE session_id=:session_id"
            ),
            {
                "session_id": str(session_id),
                "now": now,
                "expires_at": now + timedelta(seconds=SESSION_TTL_SECONDS),
            },
        )
        await self.session.commit()

    async def list_sessions(self, owner_subject: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = (
            await self.session.execute(
                text(
                    """
                    SELECT session_id, owner_subject, owner_roles, created_at, updated_at, expires_at
                    FROM chat_sessions
                    WHERE owner_subject=:owner_subject AND expires_at>CURRENT_TIMESTAMP
                    ORDER BY updated_at DESC LIMIT :limit
                    """
                ),
                {"owner_subject": owner_subject, "limit": min(max(int(limit), 1), 100)},
            )
        ).mappings().all()
        return [dict(row) for row in rows]

    async def add_message(
        self,
        session_id: UUID | str,
        role: str,
        content: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        normalized_role = str(role).strip().lower()
        if normalized_role not in {"user", "assistant", "tool"}:
            raise ValueError("invalid_chat_message_role")
        bounded = str(content)[:16000]
        row = (
            await self.session.execute(
                text(
                    """
                    INSERT INTO chat_messages
                    (message_id, session_id, role, content, metadata, created_at)
                    VALUES (:message_id, :session_id, :role, :content, CAST(:metadata AS jsonb), CURRENT_TIMESTAMP)
                    RETURNING message_id, session_id, role, content, metadata, created_at
                    """
                ),
                {
                    "message_id": uuid4(),
                    "session_id": str(session_id),
                    "role": normalized_role,
                    "content": bounded,
                    "metadata": _json(metadata or {}),
                },
            )
        ).mappings().one()
        await self.session.commit()
        return dict(row)

    async def history(self, session_id: UUID | str, limit: int = HISTORY_LIMIT) -> list[dict[str, Any]]:
        rows = (
            await self.session.execute(
                text(
                    """
                    SELECT message_id, session_id, role, content, metadata, created_at
                    FROM (
                        SELECT message_id, session_id, role, content, metadata, created_at
                        FROM chat_messages WHERE session_id=:session_id
                        ORDER BY created_at DESC LIMIT :limit
                    ) recent
                    ORDER BY created_at ASC
                    """
                ),
                {"session_id": str(session_id), "limit": min(max(int(limit), 1), HISTORY_LIMIT)},
            )
        ).mappings().all()
        return [dict(row) for row in rows]

    async def create_proposal(
        self,
        *,
        session_id: UUID | str,
        incident_id: UUID | str,
        owner_subject: str,
        tool_name: str,
        action: str,
        target: str,
        parameters: dict[str, Any],
        risk_level: str,
        binding_digest: str,
    ) -> dict[str, Any]:
        proposal_id = uuid4()
        now = _utcnow()
        expires_at = now + timedelta(seconds=PROPOSAL_TTL_SECONDS)
        row = (
            await self.session.execute(
                text(
                    """
                    INSERT INTO chat_action_proposals
                    (proposal_id, session_id, incident_id, owner_subject, tool_name, action, target,
                     parameters, risk_level, status, binding_digest, expires_at, created_at, updated_at)
                    VALUES (:proposal_id, :session_id, :incident_id, :owner_subject, :tool_name, :action,
                            :target, CAST(:parameters AS jsonb), :risk_level, 'pending', :binding_digest,
                            :expires_at, :now, :now)
                    RETURNING proposal_id, session_id, incident_id, owner_subject, tool_name, action, target,
                              parameters, risk_level, status, binding_digest, approval_id, execution_result,
                              expires_at, created_at, updated_at
                    """
                ),
                {
                    "proposal_id": proposal_id,
                    "session_id": str(session_id),
                    "incident_id": str(incident_id),
                    "owner_subject": owner_subject,
                    "tool_name": tool_name,
                    "action": action,
                    "target": target,
                    "parameters": _json(parameters),
                    "risk_level": risk_level,
                    "binding_digest": binding_digest,
                    "expires_at": expires_at,
                    "now": now,
                },
            )
        ).mappings().one()
        await self.session.commit()
        return dict(row)

    async def get_proposal(self, proposal_id: UUID | str, owner_subject: str) -> Optional[dict[str, Any]]:
        row = (
            await self.session.execute(
                text(
                    """
                    SELECT proposal_id, session_id, incident_id, owner_subject, tool_name, action, target,
                           parameters, risk_level, status, binding_digest, approval_id, execution_result,
                           expires_at, created_at, updated_at
                    FROM chat_action_proposals
                    WHERE proposal_id=:proposal_id AND owner_subject=:owner_subject
                    """
                ),
                {"proposal_id": str(proposal_id), "owner_subject": owner_subject},
            )
        ).mappings().first()
        if not row:
            return None
        record = dict(row)
        if record.get("status") == "pending" and record.get("expires_at") <= _utcnow():
            await self.session.execute(
                text(
                    "UPDATE chat_action_proposals SET status='expired', updated_at=CURRENT_TIMESTAMP "
                    "WHERE proposal_id=:proposal_id AND status='pending'"
                ),
                {"proposal_id": str(proposal_id)},
            )
            await self.session.commit()
            record["status"] = "expired"
        return record

    async def transition_proposal(
        self,
        proposal_id: UUID | str,
        *,
        expected_status: str,
        new_status: str,
        approval_id: UUID | str | None = None,
        execution_result: Optional[dict[str, Any]] = None,
    ) -> Optional[dict[str, Any]]:
        allowed = {"pending", "confirmed", "rejected", "executed", "failed", "expired"}
        if expected_status not in allowed or new_status not in allowed:
            raise ValueError("invalid_chat_proposal_status")
        row = (
            await self.session.execute(
                text(
                    """
                    UPDATE chat_action_proposals
                    SET status=:new_status,
                        approval_id=COALESCE(:approval_id, approval_id),
                        execution_result=CASE WHEN :execution_result IS NULL THEN execution_result
                                              ELSE CAST(:execution_result AS jsonb) END,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE proposal_id=:proposal_id AND status=:expected_status
                    RETURNING proposal_id, session_id, incident_id, owner_subject, tool_name, action, target,
                              parameters, risk_level, status, binding_digest, approval_id, execution_result,
                              expires_at, created_at, updated_at
                    """
                ),
                {
                    "proposal_id": str(proposal_id),
                    "expected_status": expected_status,
                    "new_status": new_status,
                    "approval_id": str(approval_id) if approval_id else None,
                    "execution_result": _json(execution_result) if execution_result is not None else None,
                },
            )
        ).mappings().first()
        await self.session.commit()
        return dict(row) if row else None
