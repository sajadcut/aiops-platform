"""Signing preflight must not disclose secret or confuse validator PASS with apply readiness."""
from apps.config_change_authorization import config_signing_ready, create_claim
from apps.api.config_change_review import _review_progress


def _report():
    return _review_progress(
        status="approved", decision="request_change_approval",
        proposal={"service": "nginx", "config_file": "/etc/nginx/nginx.conf",
                  "validation_status": "UNVERIFIED"},
        approval={
            "approval_id": "81a79d63-8c04-42ee-89f7-b055b91e5f2d",
            "status": "approved",
            "metadata": {"isolated_validation": True,
                         "validation_scope": "nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies"},
        },
    )


def test_missing_signing_key_does_not_erase_verified_validation(monkeypatch):
    monkeypatch.delenv("AIOPS_CONFIG_APPLY_SIGNING_SECRET", raising=False)
    assert config_signing_ready() is False
    report = _report()
    assert report["validation_status"] == "PASSED"
    assert report["approval_status"] == "approved"
    assert report["execution_prerequisites"]["api_signing_key"] == "missing"
    assert report["execution_prerequisites"]["vm_mcp_signing_key"] == "not_checked"
    assert report["execution_prerequisites"]["execution_ready"] is False


def test_configured_signing_key_only_proves_api_side(monkeypatch):
    private_value = "s3cur3-n0ndefault-secret-for-tests-123456789"
    monkeypatch.setenv("AIOPS_CONFIG_APPLY_SIGNING_SECRET", private_value)
    assert config_signing_ready() is True
    report = _report()
    assert report["execution_prerequisites"]["api_signing_key"] == "configured"
    assert report["execution_prerequisites"]["signing_key_match"] == "not_checked"
    assert report["execution_prerequisites"]["execution_ready"] is False
    assert private_value not in repr(report)
