"""Regression: sign recovery scope and never start from a config-only approval."""
import pytest

from apps.config_change_authorization import create_claim, verify_claim
from apps.api.config_change_review import ConfigReviewResponse, _review_progress
from integrations.vm.governed_config_change import _start_after_approved_config_apply


@pytest.fixture
def signing_token(monkeypatch):
    monkeypatch.setenv("MCP_BEARER_TOKEN",
                       "test-bearer-strong-9b22afbbf819421f8fe6dc8a422ef404")


def _claim(start=False):
    return create_claim(
        approval_id="81a79d63-8c04-42ee-89f7-b055b91e5f2d",
        incident_id="abcd5f51-3b4d-4319-bfe0-1ff7e4a5d090",
        target="192.0.2.5", service="nginx", config_file="/etc/nginx/nginx.conf",
        original_sha256="a" * 64, candidate_sha256="b" * 64,
        proposed_change="remove_extra_opening_brace",
        start_service_after_apply=start,
    )


def test_recovery_scope_is_signed_and_cannot_be_added_after_approval(signing_token):
    basic, basic_sig = _claim()
    assert "recovery_action" not in basic
    verify_claim(basic, basic_sig, target="192.0.2.5", service="nginx")
    with pytest.raises(PermissionError, match="signature_invalid"):
        verify_claim({**basic, "recovery_action": "start_service"}, basic_sig,
                     target="192.0.2.5", service="nginx")
    recovery, signature = _claim(True)
    assert recovery["recovery_action"] == "start_service"
    verify_claim(recovery, signature, target="192.0.2.5", service="nginx")
    with pytest.raises(PermissionError, match="signature_invalid"):
        verify_claim({key: value for key, value in recovery.items()
                      if key != "recovery_action"}, signature,
                     target="192.0.2.5", service="nginx")
    with pytest.raises(PermissionError, match="recovery_scope"):
        verify_claim({**recovery, "recovery_action": "restart_service"}, signature,
                     target="192.0.2.5", service="nginx")


def test_existing_config_only_ticket_remains_config_only():
    response = _review_progress(
        status="approved", decision="request_change_approval",
        proposal={"service": "nginx"},
        approval={"approval_id": "81a79d63-8c04-42ee-89f7-b055b91e5f2d",
                  "status": "approved", "metadata": {"isolated_validation": True}},
    )
    assert response["start_service_after_apply"] is False
    payload = ConfigReviewResponse(
        decision="request_change_approval",
        expected_original_sha256="a"*64, expected_candidate_sha256="b"*64,
    )
    assert payload.start_service_after_apply is False


@pytest.mark.asyncio
async def test_start_once_after_approved_repair_and_verify_fresh_systemd():
    actions = []
    class Edge:
        async def service_status(self, target, service):
            actions.append("status")
            state = "failed" if actions.count("status") == 1 else "active"
            return {"success": True, "load_state": "loaded", "active_state": state,
                    "healthy": state == "active"}
        async def start_service(self, target, service):
            actions.append("start")
            return {"success": True}
    outcome = await _start_after_approved_config_apply(
        Edge(), target="192.0.2.5", service="nginx")
    assert actions == ["status", "start", "status"]
    assert outcome == {"attempted": True, "status": "systemd_active",
                       "service_recovery_confirmed": True}


@pytest.mark.asyncio
async def test_no_unnecessary_start_when_service_is_already_running():
    class Edge:
        async def service_status(self, target, service):
            return {"success": True, "load_state": "loaded",
                    "active_state": "active", "healthy": True}
        async def start_service(self, target, service):
            raise AssertionError("already active: must not start")
    result = await _start_after_approved_config_apply(
        Edge(), target="192.0.2.5", service="nginx")
    assert result["attempted"] is False
    assert result["status"] == "already_active"


@pytest.mark.asyncio
async def test_failed_preflight_or_start_never_fakes_recovery():
    class Edge:
        async def service_status(self, target, service):
            return {"success": True, "load_state": "loaded",
                    "active_state": "failed", "healthy": False}
        async def start_service(self, target, service):
            return {"success": False}
    outcome = await _start_after_approved_config_apply(
        Edge(), target="192.0.2.5", service="nginx")
    assert outcome["attempted"] is True
    assert outcome["status"] == "start_failed"
    assert outcome["service_recovery_confirmed"] is False


@pytest.mark.asyncio
async def test_unknown_state_never_starts():
    class Edge:
        async def service_status(self, target, service):
            return {"success": True, "load_state": "loaded",
                    "active_state": "activating"}
        async def start_service(self, target, service):
            raise AssertionError("do not start while transitioning")
    outcome = await _start_after_approved_config_apply(
        Edge(), target="192.0.2.5", service="nginx")
    assert outcome["status"] == "service_state_not_startable"
