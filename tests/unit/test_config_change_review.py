"""Config-review operator intent is not a production write approval."""
import pytest
from pydantic import ValidationError

from apps.api.config_change_review import (
    ConfigReviewResponse, _matching_proposal, _hash,
)


def proposal():
    return {
        "status": "candidate_proposed", "service": "nginx",
        "config_file": "/etc/nginx/nginx.conf",
        "original_sha256": "a" * 64,
        "candidate_sha256": "b" * 64,
        "validation_status": "STAGED_PASS_NOT_ISOLATED",
        "execution_authority": False, "apply_eligible": False,
    }


def response(decision="request_isolated_validation"):
    return ConfigReviewResponse(
        decision=decision,
        expected_original_sha256="a" * 64,
        expected_candidate_sha256="b" * 64,
    )


def test_operator_response_binds_both_config_hashes_to_server_checkpoint():
    assert _matching_proposal(proposal(), response())
    assert _matching_proposal(proposal(), response("reject"))
    assert _hash("a" * 64)
    assert not _hash("a" * 63)


@pytest.mark.parametrize("key,value", [
    ("status", "needs_read_only_config"),
    ("status", "staging_failed"),
    ("service", "another-service"),
    ("execution_authority", True),
    ("apply_eligible", True),
    ("original_sha256", None),
    ("candidate_sha256", None),
    ("candidate_sha256", "b" * 63),
])
def test_review_rejects_untrusted_or_incomplete_proposals(key,value):
    p=proposal()
    p[key]=value
    assert not _matching_proposal(p, response())


def test_operator_intent_cannot_be_approval_or_apply_command():
    p=proposal()
    assert _matching_proposal(p,response())
    assert p["validation_status"]=="STAGED_PASS_NOT_ISOLATED"
    assert p["execution_authority"] is False
    assert p["apply_eligible"] is False


def test_api_is_guarded_and_exposes_no_execution_authority():
    from fastapi import FastAPI
    from apps.api.config_change_review import router
    import inspect
    import apps.api.main as main
    assert '(config_change_review.router, ["Configuration Review"])' in inspect.getsource(main)
    isolated=FastAPI()
    isolated.include_router(router,prefix="/api/v1")
    matching=[
        (getattr(r,"path",None), sorted(getattr(r,"methods",set()) or ()))
        for r in isolated.routes if "configuration-review" in str(getattr(r,"path",""))
    ]
    assert any(path=="/api/v1/incidents/{incident_id}/configuration-review-response"
               and "POST" in methods for path,methods in matching), matching
    route=next(r for r in isolated.routes if getattr(r,"path",None)=="/api/v1/incidents/{incident_id}/configuration-review-response"
               and "POST" in getattr(r,"methods",set()))
    deps=[d.call for d in route.dependant.dependencies]
    assert deps
    # API handler enforces a second explicit high-risk permission, beyond
    # the project default read:incident capability.
    from inspect import getsource
    source=getsource(route.endpoint)
    assert 'require_permission("approve:high_risk")' in source
    assert "ExecutionRequest" not in source
    assert "start_service" not in source


def test_proposed_response_schema_does_not_accept_bogus_hash_types():
    with pytest.raises(ValidationError):
        ConfigReviewResponse(decision="request_isolated_validation",
                             expected_original_sha256=None,
                             expected_candidate_sha256=None)
