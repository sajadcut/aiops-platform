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


async def _seed(
    owner: str,
    *,
    tool_name: str,
    action: str,
    target: str,
    parameters: dict,
):
    incident_id = str(uuid4())
    async with AsyncSessionLocal() as db:
        store = ChatStore(db)
        session = await store.create_session(owner, ["sre"])
        await IncidentRepository(db).upsert_incident(
            incident_id=incident_id,
            source="chatbot",
            service=target,
            severity="high",
            summary=f"chatbot write acceptance {action}",
            status="open",
            context={"chatbot": {"session_id": str(session["session_id"]), "requested_by": owner}},
        )
        await db.commit()
        canonical = execution_intent(
            incident_id=incident_id,
            tool_name=tool_name,
            action=action,
            target=target,
            parameters=parameters,
            timeout=30,
            rollback=False,
        )
        proposal = await store.create_proposal(
            session_id=session["session_id"],
            incident_id=incident_id,
            owner_subject=owner,
            tool_name=tool_name,
            action=action,
            target=target,
            parameters=parameters,
            risk_level="high",
            binding_digest=intent_digest(canonical),
        )
    return session["session_id"], incident_id, proposal


async def _cleanup(owner: str, session_id, incident_id: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM chat_sessions WHERE session_id=:id"), {"id": str(session_id)})
        await db.execute(text("DELETE FROM incidents WHERE id=:id"), {"id": incident_id})
        await db.execute(text("DELETE FROM audit_events WHERE actor=:owner"), {"owner": owner})
        await db.commit()


@pytest.mark.asyncio(loop_scope="session")
async def test_expired_proposal_is_rejected_before_approval_or_execution(monkeypatch):
    owner = "chat-expired-sre"
    session_id, incident_id, proposal = await _seed(
        owner,
        tool_name="ssh_vm",
        action="restart_service",
        target="vm01",
        parameters={"service": "nginx"},
    )
    identity = Identity(subject=owner, roles=("sre",))
    calls = []

    async def forbidden_execute(request):
        calls.append(request)
        raise AssertionError("expired proposal must not execute")

    monkeypatch.setattr(ExecutionService, "execute", staticmethod(forbidden_execute))
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE chat_action_proposals SET expires_at=CURRENT_TIMESTAMP - INTERVAL '1 minute' WHERE proposal_id=:id"),
            {"id": str(proposal["proposal_id"])},
        )
        await db.commit()

    with pytest.raises(HTTPException) as blocked:
        await ChatbotService().decide(identity, proposal["proposal_id"], True)
    assert blocked.value.status_code == 409
    assert blocked.value.detail == "chat_action_proposal_expired"
    assert calls == []

    async with AsyncSessionLocal() as db:
        approvals = (
            await db.execute(text("SELECT count(*) FROM approvals WHERE incident_id=:id"), {"id": incident_id})
        ).scalar_one()
        assert approvals == 0
    await _cleanup(owner, session_id, incident_id)


@pytest.mark.asyncio(loop_scope="session")
async def test_rejecting_pending_proposal_creates_no_approval_and_executes_nothing(monkeypatch):
    owner = "chat-reject-sre"
    session_id, incident_id, proposal = await _seed(
        owner,
        tool_name="ssh_vm",
        action="restart_service",
        target="vm01",
        parameters={"service": "nginx"},
    )
    identity = Identity(subject=owner, roles=("sre",))
    calls = []

    async def forbidden_execute(request):
        calls.append(request)
        raise AssertionError("rejected proposal must not execute")

    monkeypatch.setattr(ExecutionService, "execute", staticmethod(forbidden_execute))
    result = await ChatbotService().decide(identity, proposal["proposal_id"], False)
    assert result.kind == "execution_result"
    assert result.data == {"status": "rejected"}
    assert calls == []

    async with AsyncSessionLocal() as db:
        saved = await ChatStore(db).get_proposal(proposal["proposal_id"], owner)
        assert saved["status"] == "rejected"
        approvals = (
            await db.execute(text("SELECT count(*) FROM approvals WHERE incident_id=:id"), {"id": incident_id})
        ).scalar_one()
        assert approvals == 0
    await _cleanup(owner, session_id, incident_id)


@pytest.mark.asyncio(loop_scope="session")
async def test_confirmed_kubernetes_restart_uses_bound_execution_and_consumed_approval(monkeypatch):
    owner = "chat-k8s-write-sre"
    session_id, incident_id, proposal = await _seed(
        owner,
        tool_name="kubernetes_mcp",
        action="restart_workload",
        target="payment-api",
        parameters={"namespace": "payments"},
    )
    identity = Identity(subject=owner, roles=("sre",))
    calls = []

    async def fake_execute(request):
        calls.append(request)
        return ExecutionResult(
            success=True,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            result={"success": True, "workload": "payment-api"},
            approval_id=request.approval_id,
        )

    async def fake_verify(self, proposal_row, before_snapshot=None):
        return {"verified": True, "source": "fake_kubernetes_mcp", "result": {"rollout_complete": True}}

    async def fake_snapshot(self, proposal_row):
        return {
            "source": "fake_kubernetes_mcp",
            "state": {},
            "result": {},
            "context": {"live_evidence": {"evidence": []}},
        }

    monkeypatch.setattr(ExecutionService, "execute", staticmethod(fake_execute))
    monkeypatch.setattr(ChatbotService, "_collect_mutation_snapshot", fake_snapshot)
    monkeypatch.setattr(ChatbotService, "_verify_mutation", fake_verify)

    result = await ChatbotService().decide(identity, proposal["proposal_id"], True)
    assert result.kind == "execution_result"
    assert calls and calls[0].tool_name == "kubernetes_mcp"
    assert calls[0].action == "restart_workload"
    assert calls[0].target == "payment-api"
    assert calls[0].parameters == {"namespace": "payments"}
    assert calls[0].incident_id == incident_id
    assert calls[0].approval_granted is True
    assert calls[0].approval_id

    async with AsyncSessionLocal() as db:
        saved = await ChatStore(db).get_proposal(proposal["proposal_id"], owner)
        assert saved["status"] == "executed"
        approval = await PostgreSQLApprovalStore(db).get(calls[0].approval_id)
        assert approval["status"] == "consumed"
    await _cleanup(owner, session_id, incident_id)
