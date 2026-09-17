from __future__ import annotations

from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ChatMessageRequest(BaseModel):
    session_id: Optional[UUID] = None
    message: str = Field(..., min_length=1, max_length=4000)


class ChatActionDecisionRequest(BaseModel):
    confirm: bool


class ActionProposalView(BaseModel):
    proposal_id: UUID
    incident_id: UUID
    action: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    requires_approval: bool = True
    expires_at: str


class ChatMessageResponse(BaseModel):
    session_id: UUID
    kind: Literal["answer", "tool_result", "action_proposal", "policy_block", "execution_result"]
    message: str
    tool: Optional[str] = None
    source: Optional[str] = None
    proposal: Optional[ActionProposalView] = None
    data: Optional[Any] = None


class ChatSessionSummary(BaseModel):
    session_id: UUID
    created_at: str
    updated_at: str
    expires_at: str


class ChatHistoryMessage(BaseModel):
    role: Literal["user", "assistant", "tool"]
    content: str
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChatHistoryResponse(BaseModel):
    session_id: UUID
    messages: list[ChatHistoryMessage]


class ChatIdentityResponse(BaseModel):
    subject: str
    roles: list[str]
    permissions: list[str]
