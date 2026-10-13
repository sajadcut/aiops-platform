"""Read-only live incident status contract and browser progress indicators."""
from pathlib import Path
from uuid import UUID
import pytest
from apps.api import incident_resources as resources

ROOT = Path(__file__).resolve().parents[2]
INCIDENT = UUID("11111111-1111-4111-8111-111111111111")

class FakeResult:
    def __init__(self, record): self.record = record
    def mappings(self): return self
    def first(self): return self.record

class FakeSession:
    def __init__(self, record): self.record = record
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc, tb): return False
    async def execute(self, statement, parameters):
        assert parameters["id"] == str(INCIDENT)
        sql = str(statement).lower()
        assert "from incidents i" in sql
        assert "workflow_checkpoints" in sql
        assert "approvals" in sql
        return FakeResult(self.record)

@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "checkpoint", "approval", "running", "phase"),
    [
        ("analyzing", None, None, True, "analyzing"),
        ("analyzing", "paused", "pending", False, "awaiting_approval"),
        ("analyzing", "paused", "approved", False, "awaiting_approval"),
        ("analyzing", "paused", "consumed", True, "executing"),
        ("analyzing", "completed", None, False, "completed"),
        ("analyzing", "failed", None, False, "completed"),
        ("open", "completed", None, False, "completed"),
        ("resolved", "completed", "consumed", False, "completed"),
    ],
)
async def test_live_analysis_status_distinguishes_running_from_approval(
    monkeypatch, status, checkpoint, approval, running, phase,
):
    fake = FakeSession({
        "incident_status": status, "checkpoint_status": checkpoint,
        "checkpoint_version": 3 if checkpoint else None,
        "current_node": "rca" if checkpoint else None,
        "approval_status": approval, "approval_id": None,
    })
    monkeypatch.setattr(resources, "AsyncSessionLocal", lambda: fake)
    result = await resources.get_incident_analysis_status(INCIDENT)
    assert result["incident_status"] == status
    assert result["analysis_in_progress"] is running
    assert result["analysis_phase"] == phase
    assert result["approval"]["status"] == approval
    assert result["incident_id"] == str(INCIDENT)
    assert "evidence" not in result and "audit" not in result

def test_live_progress_polling_preserves_governed_approval_controls():
    index = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    control = (ROOT / "dashboards/control-center.js").read_text(encoding="utf-8")
    detail = (ROOT / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    page = (ROOT / "dashboards/incident-command-room.html").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/incident-command-room.css").read_text(encoding="utf-8")
    assert 'id="incidentLiveSync"' in index
    assert "incident-activity-spinner" in index
    assert "refreshIncidentQueue" in control
    assert "setInterval(() => { void refreshIncidentQueue(); }, 6000)" in control
    assert 'id="ic-analysis-progress"' in page
    assert "base+'/analysis-status'" in detail
    assert "setInterval(()=>{void pollLifecycle();},6000)" in detail
    assert "if(state.busy || state.historic)return;" in detail
    assert "await load({preserveHistory:true})" in detail
    assert "prefers-reduced-motion:reduce" in css
    assert "api('/api/v1/approvals/'+encodeURIComponent(id)+'/approve',{method:'POST'})" in detail
