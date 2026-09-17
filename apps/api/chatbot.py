from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from apps.chatbot.models import (
    ChatActionDecisionRequest,
    ChatHistoryMessage,
    ChatHistoryResponse,
    ChatIdentityResponse,
    ChatMessageRequest,
    ChatMessageResponse,
    ChatSessionRenameRequest,
    ChatSessionSummary,
)
from apps.chatbot.reliable_service import OperationsCopilotService
from apps.chatbot.store import ChatStore, HISTORY_LIMIT
from apps.chatbot.streaming import chatbot_streaming_response
from apps.security.auth import require_permission
from apps.security.rbac import POLICIES
from database import AsyncSessionLocal
from domain.contracts.rate_limit import rate_limiter_strict


router = APIRouter(prefix="/chatbot")
service = OperationsCopilotService()


def _iso(value) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _session_summary(row) -> ChatSessionSummary:
    return ChatSessionSummary(
        session_id=row["session_id"],
        title=row.get("title"),
        created_at=_iso(row["created_at"]),
        updated_at=_iso(row["updated_at"]),
        expires_at=_iso(row["expires_at"]),
    )


@router.get("/me", response_model=ChatIdentityResponse)
async def chatbot_me(identity=Depends(require_permission("read:incident"))):
    permissions = sorted(
        {
            permission
            for role in identity.roles
            if role in POLICIES
            for permission in POLICIES[role].permissions
        }
    )
    return ChatIdentityResponse(subject=identity.subject, roles=list(identity.roles), permissions=permissions)


@router.post(
    "/message",
    response_model=ChatMessageResponse,
    dependencies=[Depends(rate_limiter_strict)],
)
async def chatbot_message(
    payload: ChatMessageRequest,
    identity=Depends(require_permission("read:incident")),
):
    """Backward-compatible request/response Chatbot API."""
    return await service.message(identity, payload)


@router.post(
    "/message/stream",
    dependencies=[Depends(rate_limiter_strict)],
)
async def chatbot_message_stream(
    payload: ChatMessageRequest,
    request: Request,
    identity=Depends(require_permission("read:incident")),
):
    """SSE transport with heartbeat and a typed terminal outcome."""
    return await chatbot_streaming_response(
        service,
        identity,
        payload,
        request_id=getattr(request.state, "request_id", None),
    )


@router.get("/sessions", response_model=list[ChatSessionSummary])
async def chatbot_sessions(identity=Depends(require_permission("read:incident"))):
    async with AsyncSessionLocal() as db:
        rows = await ChatStore(db).list_sessions(identity.subject)
    return [_session_summary(row) for row in rows]


@router.patch("/sessions/{session_id}", response_model=ChatSessionSummary)
async def chatbot_rename_session(
    session_id: UUID,
    payload: ChatSessionRenameRequest,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        row = await ChatStore(db).rename_session(session_id, identity.subject, payload.title)
    if row is None:
        raise HTTPException(status_code=404, detail="chat_session_not_found")
    return _session_summary(row)


@router.delete("/sessions/{session_id}", status_code=204)
async def chatbot_delete_session(
    session_id: UUID,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        deleted = await ChatStore(db).archive_session(session_id, identity.subject)
    if not deleted:
        raise HTTPException(status_code=404, detail="chat_session_not_found")
    return Response(status_code=204)


@router.get("/sessions/{session_id}/history", response_model=ChatHistoryResponse)
async def chatbot_history(
    session_id: UUID,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        store = ChatStore(db)
        session = await store.get_session(session_id, identity.subject)
        if session is None:
            raise HTTPException(status_code=404, detail="chat_session_not_found")
        rows = await store.history(session_id, HISTORY_LIMIT)
    return ChatHistoryResponse(
        session_id=session_id,
        messages=[
            ChatHistoryMessage(
                role=row["role"],
                content=row["content"],
                created_at=_iso(row["created_at"]),
                metadata=dict(row.get("metadata") or {}),
            )
            for row in rows
        ],
    )


@router.post(
    "/actions/{proposal_id}/decision",
    response_model=ChatMessageResponse,
    dependencies=[Depends(rate_limiter_strict)],
)
async def chatbot_action_decision(
    proposal_id: UUID,
    payload: ChatActionDecisionRequest,
    identity=Depends(require_permission("read:incident")),
):
    return await service.decide(identity, proposal_id, payload.confirm)
