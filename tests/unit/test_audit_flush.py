import pytest

from apps.audit_service import AuditService


class FakeAuditStore:
    def __init__(self):
        self.events = []

    async def append(self, event):
        self.events.append(event)


@pytest.mark.asyncio
async def test_audit_flush_persists_and_clears_incident_events():
    AuditService.clear()
    AuditService.record("test_event", "unit", incident_id="inc-1")
    AuditService.record("other_event", "unit", incident_id="inc-2")
    store = FakeAuditStore()

    count = await AuditService.flush_to_store(store, incident_id="inc-1")

    assert count == 1
    assert [event["event_type"] for event in store.events] == ["test_event"]
    assert len(AuditService.list_events(incident_id="inc-1")) == 0
    assert len(AuditService.list_events(incident_id="inc-2")) == 1
    AuditService.clear()
