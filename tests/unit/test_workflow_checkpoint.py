import pytest

from apps.orchestrator.workflow_store import WorkflowCheckpointStore


@pytest.mark.asyncio
async def test_checkpoint_store_contract_methods_exist():
    assert callable(WorkflowCheckpointStore.save)
    assert callable(WorkflowCheckpointStore.load)
    assert callable(WorkflowCheckpointStore.mark_completed)
    assert callable(WorkflowCheckpointStore.mark_failed)
