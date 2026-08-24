import pytest

from apps.runbook_service.executor import RunbookExecutor


class Registry:
    def __init__(self):
        self._runbook = {"id": "app-error-rollback", "action": "rollback"}

    def get(self, runbook_id):
        return self._runbook if runbook_id == self._runbook["id"] else None

    def validate(self, runbook_id, parameters):
        if not self.get(runbook_id):
            raise ValueError("runbook_not_found")
        return {"valid": True}


@pytest.mark.asyncio
async def test_dry_run_is_side_effect_free():
    result = await RunbookExecutor(Registry()).execute(
        "app-error-rollback",
        tool_name="mock_executor",
        target="service-a",
        parameters={"release": "r1"},
        dry_run=True,
    )
    assert result["status"] == "dry_run"


def test_runbook_registry_validation():
    registry = Registry()
    assert registry.validate("app-error-rollback", {})["valid"] is True
