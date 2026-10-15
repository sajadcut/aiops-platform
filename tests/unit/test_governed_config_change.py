"""Safety regressions for staged, signed, one-shot config repair."""
import base64
import hashlib
import subprocess
from pathlib import Path

import pytest

from apps.config_change_authorization import create_claim, sign_root_guard, verify_claim
from integrations.vm.governed_config_change import (
    rebuild_nginx_candidate, run_governed_change,
)

SOURCE = b"server 127.0.0.1 {{\n"
CANDIDATE = b"server 127.0.0.1 {\n"
PATH = "/etc/nginx/nginx.conf"


def params():
    return {
        "config_file": PATH,
        "original_sha256": hashlib.sha256(SOURCE).hexdigest(),
        "candidate_sha256": hashlib.sha256(CANDIDATE).hexdigest(),
        "proposed_change": "remove_extra_opening_brace",
    }


def test_nginx_candidate_reconstructed_only_from_same_hash_bound_source():
    p = params()
    assert rebuild_nginx_candidate(
        encoded=base64.b64encode(SOURCE).decode(), path=PATH, line=1,
        error='unexpected "{"', **{k: p[k] for k in ("original_sha256", "candidate_sha256")}
    ).encode() == CANDIDATE
    with pytest.raises(ValueError, match="config_source_hash_drift"):
        rebuild_nginx_candidate(
            encoded=base64.b64encode(b"changed {{\n").decode(), path=PATH,
            line=1, error='unexpected "{"',
            **{k: p[k] for k in ("original_sha256", "candidate_sha256")},
        )


def test_config_execution_signed_claim_is_exact_scoped_and_short_lived(monkeypatch):
    monkeypatch.setenv("MCP_BEARER_TOKEN", "a-real-unique-secret-for-tests-1234567890")
    values = params()
    claims, sig = create_claim(
        approval_id="c7767949-531b-4c42-87c5-e7f1795afc44",
        incident_id="7c926882-1024-45be-a87f-3ea65677c526",
        target="10.248.16.82", service="nginx", **values,
    )
    verify_claim(claims, sig, target="10.248.16.82", service="nginx")
    monkeypatch.setenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY",
                      base64.b64encode(bytes([7]) * 32).decode())
    assert len(sign_root_guard(claims)) == 88
    with pytest.raises(PermissionError):
        verify_claim({**claims, "target": "10.248.16.83"}, sig,
                     target="10.248.16.83", service="nginx")
    with pytest.raises(PermissionError):
        verify_claim({**claims, "candidate_sha256": "c"*64}, sig,
                     target="10.248.16.82", service="nginx")
    monkeypatch.delenv("MCP_BEARER_TOKEN")
    with pytest.raises(PermissionError, match="mcp_bearer_token"):
        create_claim(approval_id="a", incident_id="b", target="host",
                     service="nginx", **values)


@pytest.mark.asyncio
async def test_worker_validates_exact_candidate_without_ssh_secret_leak():
    calls = []

    class Connector:
        _validate_target = staticmethod(lambda target: None)
        _validate_service = staticmethod(lambda service: None)

        async def config_validate(self, target, service):
            return {"success": True, "supported": True, "valid": False,
                    "config_file": PATH, "error_line": 1, "syntax_error": 'unexpected "{"'}

        async def _sudo(self, target, command, *, stdin_data=None):
            return await self._run(target, "sudo -n " + command, stdin_data=stdin_data)

        async def _run(self, target, command, *, stdin_data=None):
            calls.append((command, stdin_data))
            if "/bin/sh -s --" in command:
                return {"success": True, "stdout": "VALIDATED"}
            return {"success": True, "stdout": base64.b64encode(SOURCE).decode()}

    result = await run_governed_change(
        Connector(), action="validate", target="10.248.16.82",
        service="nginx", **params(),
    )
    assert result["success"] is True
    assert result["isolated_validation"] is True
    assert result["production_write_performed"] is False
    assert len(calls) == 2
    assert base64.b64encode(CANDIDATE).decode() in calls[1][1]
    assert CANDIDATE.decode() not in calls[1][1]
    assert SOURCE.decode() not in calls[1][0]
    assert CANDIDATE.decode() not in calls[1][0]


@pytest.mark.asyncio
async def test_unknown_vendor_or_forged_config_never_validates(monkeypatch):
    class NeverUsed:
        _validate_target = staticmethod(lambda _: None)
        _validate_service = staticmethod(lambda _: None)

    p = params()
    invalid = await run_governed_change(
        NeverUsed(), action="validate", target="10.248.16.82",
        service="haproxy", **p,
    )
    assert invalid["status"] == "unsupported_vendor_apply_adapter"
    assert invalid["success"] is False
    with pytest.raises(PermissionError):
        await run_governed_change(
            NeverUsed(), action="delete", target="10.248.16.82",
            service="nginx", **p,
        )


def test_remote_helper_is_shell_only_and_refuses_generic_execution():
    root = Path(__file__).resolve().parents[2]
    helper = root / "scripts/vm/aiops-config-guard"
    script = helper.read_text()
    check = subprocess.run(["sh", "-n", str(helper)], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    assert "unshare -m --propagation private" in script
    assert "sha256sum" in script and "flock -x" in script
    assert "ROLLED_BACK" in script and "ROLLBACK_FAILED" in script
    assert "/etc/aiops/config-change-verify.pem" in script
    assert "openssl pkeyutl -verify" in script
    assert "openssl dgst -sha256 -hmac" not in script
    assert "config-claims" in script
    assert "sudo sh" not in script and "python" not in script.lower()
    # Without root and a precise 5- or 10-field contract it cannot write.
    assert "/usr/sbin/nginx -t" in script


def test_config_routes_require_operator_permission_and_are_registered():
    from fastapi.testclient import TestClient
    from apps.api.main import app
    client = TestClient(app)
    ident = "d7562af6-a977-4dc2-8965-bd6dc752f2ce"
    assert client.post("/api/v1/approvals/" + ident + "/validate-config").status_code == 401
    assert client.post("/api/v1/approvals/" + ident + "/execute-config").status_code == 401


def test_openssl_root_verifier_matches_worker_ed25519_signature(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    seed = bytes([13]) * 32
    monkeypatch.setenv("AIOPS_CONFIG_GUARD_ED25519_PRIVATE_KEY", base64.b64encode(seed).decode())
    values = params()
    claims = {
        "service": "nginx", "config_file": values["config_file"],
        "original_sha256": values["original_sha256"],
        "candidate_sha256": values["candidate_sha256"],
        "approval_id": "bad888cd-277b-4e11-a264-6e2331ed2d7a",
        "incident_id": "47583843-c814-423b-a957-a877802fae58",
        "target": "10.248.16.82", "expires": 1792091234,
    }
    sign = base64.b64decode(sign_root_guard(claims))
    data = "|".join([
        "v1", "apply", claims["service"], claims["config_file"],
        claims["original_sha256"], claims["candidate_sha256"],
        claims["approval_id"], claims["incident_id"], claims["target"],
        str(claims["expires"]),
    ]).encode()
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / "pub.pem").write_bytes(pub)
    (tmp_path / "message").write_bytes(data)
    (tmp_path / "signature").write_bytes(sign)
    command = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(tmp_path / "pub.pem"),
               "-rawin", "-in", str(tmp_path / "message"),
               "-sigfile", str(tmp_path / "signature")]
    ok = subprocess.run(command, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    (tmp_path / "message").write_bytes(data + b"tampered")
    rejected = subprocess.run(command, capture_output=True, text=True)
    assert rejected.returncode != 0


@pytest.mark.asyncio
async def test_generic_api_cannot_forge_validated_config_approval():
    from fastapi import HTTPException
    from types import SimpleNamespace
    from apps.api.execution import create_approval
    with pytest.raises(HTTPException) as exc:
        await create_approval(
            {"action": "apply_configuration_change", "tool_name": "vm_config_change",
             "metadata": {"workflow": "config_change", "isolated_validation": True}},
            identity=SimpleNamespace(subject="test-sre", roles=["sre"]),
        )
    assert exc.value.status_code == 409
    assert exc.value.detail == "use_governed_config_approval_workflow"


@pytest.mark.parametrize("service,path", [
    ("gfpapi", "/opt/gfpapi/appsettings.json"),
    ("spring-payments", "/srv/java/config/application.json"),
    ("python-api", "/etc/python-api/settings.json"),
    ("tomcat-app", "/usr/local/tomcat/conf/settings.json"),
])
@pytest.mark.asyncio
async def test_systemd_bound_json_config_approval_path_for_any_runtime(service, path):
    from integrations.vm.governed_config_change import rebuild_json_candidate
    source = '{"connectionString":"HIDDEN_SENSITIVE", "enabled":true,}\n'
    desired = '{"connectionString":"HIDDEN_SENSITIVE", "enabled":true}\n'
    expected_source = hashlib.sha256(source.encode()).hexdigest()
    expected_candidate = hashlib.sha256(desired.encode()).hexdigest()
    assert rebuild_json_candidate(
        encoded=base64.b64encode(source.encode()).decode(), path=path,
        original_sha256=expected_source, candidate_sha256=expected_candidate,
    ) == desired

    calls = []
    class Edge:
        _validate_target = staticmethod(lambda x: None)
        _validate_service = staticmethod(lambda x: None)
        async def service_config_discovery(self, target, name):
            return {"success": True, "service": name, "files": [
                {"path": path, "verified_exists": True, "source": "systemd_working_directory_inventory"}
            ]}
        async def _sudo(self, target, command, *, stdin_data=None):
            return await self._run(target, "sudo -n " + command, stdin_data=stdin_data)

        async def _run(self, target, command, *, stdin_data=None):
            calls.append((command, stdin_data))
            if "/bin/sh -s --" in command:
                assert path in command
                return {"success": True, "stdout": "VALIDATED"}
            return {"success": True, "stdout": base64.b64encode(source.encode()).decode()}

    result = await run_governed_change(
        Edge(), action="validate", target="10.248.16.82", service=service,
        config_file=path, original_sha256=expected_source,
        candidate_sha256=expected_candidate, proposed_change="remove_trailing_json_comma",
    )
    assert result["success"] is True
    assert result["validation_scope"] == "generic_json_syntax_only_service_runtime_unverified"
    assert result["production_write_performed"] is False
    assert result["vendor_validator"].startswith("jq empty")
    assert len(calls) == 2
    assert base64.b64encode(desired.encode()).decode() in calls[1][1]
    assert "HIDDEN_SENSITIVE" not in calls[1][0]
    assert "HIDDEN_SENSITIVE" not in calls[1][1]


@pytest.mark.asyncio
async def test_generic_json_proposal_requires_fresh_systemd_file_binding():
    src = '{"ok":true,}'
    class Unverified:
        _validate_target = staticmethod(lambda x: None)
        _validate_service = staticmethod(lambda x: None)
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [
                {"path": "/opt/another-service/appsettings.json", "verified_exists": True},
            ]}
        async def _sudo(self, target, command, *, stdin_data=None):
            return await self._run(target, "sudo -n " + command, stdin_data=stdin_data)

        async def _run(self, *args, **kwargs):
            raise AssertionError("must not read arbitrary unbound config")
    result = await run_governed_change(
        Unverified(), action="validate", target="10.248.16.82", service="gfpapi",
        config_file="/opt/gfpapi/appsettings.json",
        original_sha256=hashlib.sha256(src.encode()).hexdigest(),
        candidate_sha256=hashlib.sha256(src.replace(",", "").encode()).hexdigest(),
        proposed_change="remove_trailing_json_comma",
    )
    assert result["success"] is False
    assert result["status"] == "config_path_not_bound_to_service"


def test_general_guard_supports_different_approved_app_config_roots_without_runtime_python():
    helper = Path(__file__).resolve().parents[2] / "scripts/vm/aiops-config-guard"
    data = helper.read_text()
    assert "json_syntax" in data
    assert "jq empty" in data
    assert "/etc/*.json" in data and "/srv/*.json" in data and "/opt/*.json" in data
    assert "openssl pkeyutl -verify" in data
    assert "APPLIED_VERIFIED" in data and "ROLLED_BACK" in data
    assert subprocess.run(["sh", "-n", str(helper)], capture_output=True).returncode == 0


@pytest.mark.parametrize("service,path", [
    ("tomcat", "/opt/tomcat/conf/server.xml"),
    ("java-payment", "/srv/payment/config/application.xml"),
    ("custom-python", "/etc/example/service.xml"),
])
@pytest.mark.asyncio
async def test_xml_repair_flows_through_same_governed_service_neutral_validator(service, path):
    from integrations.vm.governed_config_change import rebuild_xml_candidate
    src = '<Server><Service password="DO_NOT_LEAK"/></Server></Server>\n'
    corrected = '<Server><Service password="DO_NOT_LEAK"/></Server>\n'
    old, new = (
        hashlib.sha256(src.encode()).hexdigest(),
        hashlib.sha256(corrected.encode()).hexdigest(),
    )
    from integrations.vm.general_config_review import local_config_review
    preview = local_config_review(base64.b64encode(src.encode()).decode(), path=path)
    assert preview["status"] == "candidate_proposed"
    assert preview["proposed_change"] == "remove_extra_xml_closing_tag"
    assert preview["source_hash"] == old
    assert preview["candidate_hash"] == new
    assert "DO_NOT_LEAK" not in str(preview)
    assert rebuild_xml_candidate(
        encoded=base64.b64encode(src.encode()).decode(), path=path,
        original_sha256=old, candidate_sha256=new,
    ) == corrected

    class Edge:
        _validate_target = staticmethod(lambda target: None)
        _validate_service = staticmethod(lambda service: None)
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [{"path": path, "verified_exists": True}]}
        async def _sudo(self, target, command, *, stdin_data=None):
            return await self._run(target, "sudo -n " + command, stdin_data=stdin_data)

        async def _run(self, target, command, *, stdin_data=None):
            if "/bin/sh -s --" in command:
                assert base64.b64encode(corrected.encode()).decode() in stdin_data
                return {"success": True, "stdout": "VALIDATED"}
            return {"success": True, "stdout": base64.b64encode(src.encode()).decode()}

    result = await run_governed_change(
        Edge(), action="validate", target="192.0.2.12", service=service,
        config_file=path, original_sha256=old, candidate_sha256=new,
        proposed_change="remove_extra_xml_closing_tag",
    )
    assert result["success"] is True
    assert result["validation_scope"] == "generic_xml_syntax_only_service_runtime_unverified"
    assert result["vendor_validator"].startswith("xmllint")
    assert result["production_write_performed"] is False


def test_xml_dtd_or_missing_tag_does_not_create_unsafe_fix():
    from integrations.vm.general_config_review import local_config_review
    for raw in [
        '<!DOCTYPE Server [<!ENTITY x SYSTEM "file:///etc/passwd">]><Server/>',
        '<Server><Service></Server>',
    ]:
        result = local_config_review(base64.b64encode(raw.encode()).decode(),
                                     path="/opt/tomcat/conf/server.xml")
        assert result["status"] != "candidate_proposed"
        assert result["candidate_hash"] is None
        assert result["execution_authority"] is False
    script = (Path(__file__).resolve().parents[2] / "scripts/vm/aiops-config-guard").read_text()
    assert "xmllint --nonet --noout" in script
    assert "DOCTYPE|ENTITY" in script
