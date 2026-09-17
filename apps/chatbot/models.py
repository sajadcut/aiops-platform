from __future__ import annotations

from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from domain.contracts.redaction import redact, redact_text


class ChatMessageRequest(BaseModel):
    session_id: Optional[UUID] = None
    message: str = Field(..., min_length=1, max_length=4000)


class ChatActionDecisionRequest(BaseModel):
    confirm: bool


class ChatSessionRenameRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=160)

    @field_validator("title", mode="before")
    @classmethod
    def normalize_title(cls, value: Any) -> str:
        return " ".join(redact_text(str(value or "")).split()).strip()


class ActionProposalView(BaseModel):
    proposal_id: UUID
    incident_id: UUID
    action: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    requires_approval: bool = True
    expires_at: str

    @field_validator("parameters", mode="before")
    @classmethod
    def redact_parameters(cls, value: Any) -> Any:
        return redact(value or {})


class ChatMessageResponse(BaseModel):
    session_id: UUID
    kind: Literal["answer", "tool_result", "action_proposal", "policy_block", "execution_result"]
    message: str
    tool: Optional[str] = None
    source: Optional[str] = None
    proposal: Optional[ActionProposalView] = None
    data: Optional[Any] = None

    @field_validator("message", mode="before")
    @classmethod
    def redact_message(cls, value: Any) -> str:
        return redact_text(str(value or ""))

    @field_validator("data", mode="before")
    @classmethod
    def redact_data(cls, value: Any) -> Any:
        return redact(value)


class ChatSessionSummary(BaseModel):
    session_id: UUID
    title: Optional[str] = None
    created_at: str
    updated_at: str
    expires_at: str

    @field_validator("title", mode="before")
    @classmethod
    def redact_title(cls, value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        return redact_text(str(value))[:160]


class ChatHistoryMessage(BaseModel):
    role: Literal["user", "assistant", "tool"]
    content: str
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("content", mode="before")
    @classmethod
    def redact_content(cls, value: Any) -> str:
        return redact_text(str(value or ""))

    @field_validator("metadata", mode="before")
    @classmethod
    def redact_metadata(cls, value: Any) -> Any:
        return redact(value or {})


class ChatHistoryResponse(BaseModel):
    session_id: UUID
    messages: list[ChatHistoryMessage]


class ChatIdentityResponse(BaseModel):
    subject: str
    roles: list[str]
    permissions: list[str]
