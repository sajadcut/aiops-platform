import os
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from apps.approval_service.binding import execution_intent, intent_digest
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.chatbot.service import ChatbotService
from apps.chatbot.store import ChatStore
from apps.execution_service import ExecutionResult, ExecutionService
from apps.incident_service.repository import IncidentRepository
from apps.security.oidc import Identity
from database import AsyncSessionLocal


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DB_CHATBOT_TEST") != "1",
    reason="requires migrated PostgreSQL acceptance database",
)


async def _seed_proposal(owner: str = "chatbot-db-sre"):
    session_uuid = None
    incident_id = str(uuid4())
    async with AsyncSessionLocal() as db:
        store = ChatStore(db)
        session = await store.create_session(owner, ["sre"])
        session_uuid = session["session_id"]
        await IncidentRepository(db).upsert_incident(
            incident_id=incident_id,
            source="chatbot",
            service="vm01",
            severity="high",
            summary="chatbot database acceptance",
            status="open",
            context={"chatbot": {"session_id": str(session_uuid), "requested_by": owner}},
        )
        await db.commit()
        intent = execution_intent(
            incident_id=incident_id,
            tool_name="ssh_vm",
            action="reload_service",
            target="vm01",
            parameters={"service": "nginx"},
            timeout=30,
            rollback=False,
        )
        proposal = await store.create_proposal(
            session_id=session_uuid,
            incident_id=incident_id,
            owner_subject=owner,
            tool_name="ssh_vm",
            action="reload_service",
            target="vm01",
            parameters={"service": "nginx"},
            risk_level="high",
            binding_digest=intent_digest(intent),
        )
    return session_uuid, incident_id, proposal


@pytest.mark.asyncio
async def test_chat_session_and_proposal_are_owner_scoped():
    session_id, incident_id, proposal = await _seed_proposal("chatbot-owner-a")
    async with AsyncSessionLocal() as db:
        store = ChatStore(db)
        assert await store.get_session(session_id, "chatbot-owner-a") is not None
        assert await store.get_session(session_id, "chatbot-owner-b") is None
        assert await store.get_proposal(proposal["proposal_id"], "chatbot-owner-a") is not None
        assert await store.get_proposal(proposal["proposal_id"], "chatbot-owner-b") is None
        await db.execute(text("DELETE FROM chat_sessions WHERE session_id=:id"), {"id": str(session_id)})
        await db.execute(text("DELETE FROM incidents WHERE id=:id"), {"id": incident_id})
        await db.commit()


@pytest.mark.asyncio
async def test_confirmed_vm_action_uses_durable_approval_consumption_and_is_not_replayable(monkeypatch):
    session_id, incident_id, proposal = await _seed_proposal("chatbot-exec-sre")
    identity = Identity(subject="chatbot-exec-sre", roles=("sre",))
    calls = []

    async def fake_execute(request):
        calls.append(request)
        return ExecutionResult(
            success=True,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            result={"success": True, "reloaded": "nginx"},
            approval_id=request.approval_id,
        )

    async def fake_verify(self, proposal_row):
        return {"verified": True, "source": "fake_vm_mcp", "result": {"active": True}}

    monkeypatch.setattr(ExecutionService, "execute", staticmethod(fake_execute))
    monkeypatch.setattr(ChatbotService, "_verify_mutation", fake_verify)

    result = await ChatbotService().decide(identity, proposal["proposal_id"], True)
    assert result.kind == "execution_result"
    assert calls and calls[0].tool_name == "ssh_vm"
    assert calls[0].action == "reload_service"
    assert calls[0].incident_id == incident_id
    assert calls[0].approval_granted is True
    assert calls[0].approval_id

    async with AsyncSessionLocal() as db:
        saved = await ChatStore(db).get_proposal(proposal["proposal_id"], identity.subject)
        assert saved["status"] == "executed"
        assert str(saved["approval_id"]) == calls[0].approval_id
        approval = await PostgreSQLApprovalStore(db).get(calls[0].approval_id)
        assert approval["status"] == "consumed"

    with pytest.raises(HTTPException) as replay:
        await ChatbotService().decide(identity, proposal["proposal_id"], True)
    assert replay.value.status_code == 409

    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM chat_sessions WHERE session_id=:id"), {"id": str(session_id)})
        await db.execute(text("DELETE FROM incidents WHERE id=:id"), {"id": incident_id})
        await db.execute(text("DELETE FROM audit_events WHERE actor=:actor"), {"actor": identity.subject})
        await db.commit()


@pytest.mark.asyncio
async def test_action_parameter_tampering_after_proposal_is_blocked_before_approval(monkeypatch):
    session_id, incident_id, proposal = await _seed_proposal("chatbot-tamper-sre")
    identity = Identity(subject="chatbot-tamper-sre", roles=("sre",))
    calls = []

    async def fake_execute(request):
        calls.append(request)
        raise AssertionError("tampered proposal must never reach execution")

    monkeypatch.setattr(ExecutionService, "execute", staticmethod(fake_execute))

    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE chat_action_proposals SET parameters=CAST(:params AS jsonb) WHERE proposal_id=:id"),
            {"params": '{"service":"sshd"}', "id": str(proposal["proposal_id"])},
        )
        await db.commit()

    with pytest.raises(HTTPException) as blocked:
        await ChatbotService().decide(identity, proposal["proposal_id"], True)
    assert blocked.value.status_code == 409
    assert blocked.value.detail == "chat_action_proposal_binding_mismatch"
    assert calls == []

    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM chat_sessions WHERE session_id=:id"), {"id": str(session_id)})
        await db.execute(text("DELETE FROM incidents WHERE id=:id"), {"id": incident_id})
        await db.execute(text("DELETE FROM audit_events WHERE actor=:actor"), {"actor": identity.subject})
        await db.commit()
