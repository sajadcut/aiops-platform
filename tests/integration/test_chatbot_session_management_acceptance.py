import os

import pytest
from sqlalchemy import text

from apps.chatbot.store import ChatStore
from database import AsyncSessionLocal


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DB_CHATBOT_TEST") != "1",
    reason="requires migrated PostgreSQL acceptance database",
)


@pytest.mark.asyncio(loop_scope="session")
async def test_chat_session_auto_title_rename_and_delete_preserve_governance_boundary():
    owner = "chatbot-session-v2"
    session_id = None
    try:
        async with AsyncSessionLocal() as db:
            store = ChatStore(db)
            session = await store.create_session(owner, ["viewer"])
            session_id = session["session_id"]
            await store.add_message(
                session_id,
                "user",
                "CPU سرور 10.100.6.199 چقدره؟",
                {"kind": "user"},
            )
            sessions = await store.list_sessions(owner)
            assert len(sessions) == 1
            assert sessions[0]["title"] == "CPU سرور 10.100.6.199 چقدره؟"

            renamed = await store.rename_session(session_id, owner, "بررسی سرور پرداخت")
            assert renamed is not None
            assert renamed["title"] == "بررسی سرور پرداخت"

            assert await store.archive_session(session_id, owner) is True
            assert await store.get_session(session_id, owner) is None
            assert await store.list_sessions(owner) == []
            assert await store.history(session_id) == []
    finally:
        if session_id is not None:
            async with AsyncSessionLocal() as db:
                await db.execute(text("DELETE FROM chat_sessions WHERE session_id=:id"), {"id": str(session_id)})
                await db.commit()
