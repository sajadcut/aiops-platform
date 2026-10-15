"""MCP bearer is the only config-approval signing root; do not leak its value."""
import hashlib
import hmac

import pytest

from apps.config_change_authorization import (
    _key, config_signing_ready, create_claim, verify_claim,
)
from apps.api.config_change_review import _review_progress
from domain.contracts.config import settings


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


def _valid(monkeypatch, value="aiops-test-mcp-bearer-strong-7f8b9c0d1e2f3a4b"):
    monkeypatch.setattr(settings, "MCP_BEARER_TOKEN", value)
    monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
    return value


def test_missing_mcp_bearer_does_not_erase_vendor_validation(monkeypatch):
    _valid(monkeypatch, "")
    assert config_signing_ready() is False
    report = _report()
    assert report["validation_status"] == "PASSED"
    assert report["approval_status"] == "approved"
    prereqs = report["execution_prerequisites"]
    assert prereqs["signing_source"] == "MCP_BEARER_TOKEN"
    assert prereqs["api_signing_key"] == "missing_or_weak_mcp_bearer_token"
    assert prereqs["vm_mcp_signing_key"] == "not_checked"
    assert prereqs["execution_ready"] is False


def test_same_mcp_bearer_is_domain_separated_for_signing(monkeypatch):
    token = _valid(monkeypatch)
    assert config_signing_ready() is True
    assert _key() != token.encode()
    assert _key() == hmac.new(
        token.encode(), b"aiops/configuration-apply/approval-claim/v1",
        hashlib.sha256,
    ).digest()
    prereqs = _report()["execution_prerequisites"]
    assert prereqs["api_signing_key"] == "derived_from_mcp_bearer_token"
    assert prereqs["signing_key_match"] == "not_checked"
    assert prereqs["execution_ready"] is False
    assert token not in repr(prereqs)


def test_mcp_bearer_settings_and_explicit_environment_override(monkeypatch):
    _valid(monkeypatch)
    assert config_signing_ready() is True
    monkeypatch.setenv("MCP_BEARER_TOKEN", "")
    assert config_signing_ready() is False
    monkeypatch.setenv("MCP_BEARER_TOKEN", "new-long-strong-mcp-bearer-token-abcdef123456")
    assert config_signing_ready() is True


@pytest.mark.parametrize("token", ["short", "changeme", "x" * 31, ""])
def test_weak_mcp_bearer_blocks_signing(monkeypatch, token):
    _valid(monkeypatch, token)
    assert config_signing_ready() is False
    with pytest.raises(PermissionError, match="mcp_bearer_token"):
        _key()


def test_signed_claim_cannot_be_reused_under_different_bearer(monkeypatch):
    token = _valid(monkeypatch)
    claims, signature = create_claim(
        approval_id="81a79d63-8c04-42ee-89f7-b055b91e5f2d",
        incident_id="c7b1038f-2b49-4cb9-b360-970a4aa50efc",
        target="192.0.2.3", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256="a" * 64, candidate_sha256="b" * 64,
        proposed_change="remove_extra_opening_brace",
    )
    verify_claim(claims, signature, target="192.0.2.3", service="nginx")
    assert token not in repr(claims) + signature
    monkeypatch.setattr(settings, "MCP_BEARER_TOKEN",
                        "another-test-mcp-bearer-token-with-48-characters")
    with pytest.raises(PermissionError, match="signature_invalid"):
        verify_claim(claims, signature, target="192.0.2.3", service="nginx")
    monkeypatch.setattr(settings, "MCP_BEARER_TOKEN", token)
    with pytest.raises(PermissionError, match="signature_invalid"):
        verify_claim({**claims, "candidate_sha256": "c" * 64}, signature,
                     target="192.0.2.3", service="nginx")
