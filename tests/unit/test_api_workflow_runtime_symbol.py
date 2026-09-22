import inspect

import apps.api.e2e_workflow as e2e_api
import apps.api.incidents as incidents_api
import apps.api.workflow as workflow_api
from apps.orchestrator.learning_runtime import LearningDurableWorkflowRuntime


def test_workflow_api_modules_reference_the_imported_canonical_runtime_symbol():
    assert LearningDurableWorkflowRuntime is not None

    sources = [
        inspect.getsource(e2e_api.run_e2e_workflow),
        inspect.getsource(e2e_api.resume_e2e_workflow),
        inspect.getsource(workflow_api.run_workflow),
        inspect.getsource(incidents_api.analyze_incident),
    ]

    for source in sources:
        assert "LearningLearningDurableWorkflowRuntime" not in source
        assert "LearningDurableWorkflowRuntime" in source
