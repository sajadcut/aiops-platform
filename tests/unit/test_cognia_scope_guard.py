import pytest
from fastapi import HTTPException

from apps.api.cognia_scope import reject_untrusted_knowledge_subject


def test_public_workflow_context_allows_non_scope_metadata():
    reject_untrusted_knowledge_subject({"service": "payments", "trace": "abc"})


@pytest.mark.parametrize("key", ["knowledge_subject", "knowledgeSubject"])
def test_public_workflow_context_rejects_untrusted_external_subject(key):
    with pytest.raises(HTTPException) as captured:
        reject_untrusted_knowledge_subject(
            {key: {"namespace": "customer", "externalSubjectId": "C-9381"}}
        )
    assert captured.value.status_code == 403
    assert captured.value.detail == "knowledge_subject_requires_trusted_server_binding"
