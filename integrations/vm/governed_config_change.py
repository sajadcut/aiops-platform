"""Trusted VM MCP worker for bounded hash-bound configuration operations.

Full source and candidate bytes stay in this process and SSH stdin. Neither
payload is returned to API, LLM, audit, checkpoints, or browser.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET

from domain.contracts.logging import logger
from apps.config_change_authorization import verify_claim
from integrations.vm.ephemeral_config_guard import build_ephemeral_guard
from integrations.vm.general_config_review import checked_config_path, remote_config_read_command, _remove_trailing_json_commas
from integrations.vm.nginx_config_review import (
    _checked_path, _repair_line, nginx_review_command,
)


def rebuild_nginx_candidate(*, encoded: str, path: str, line: int, error: str,
                            original_sha256: str, candidate_sha256: str) -> str:
    _checked_path(path)
    if not (isinstance(line, int) and 1 <= line <= 100000
            and re.fullmatch(r"[a-f0-9]{64}", original_sha256 or "")
            and re.fullmatch(r"[a-f0-9]{64}", candidate_sha256 or "")):
        raise ValueError("config_candidate_invalid_contract")
    source = base64.b64decode(encoded, validate=True)
    if not 1 <= len(source) <= 262144 or hashlib.sha256(source).hexdigest() != original_sha256:
        raise ValueError("config_source_hash_drift")
    data = source.decode("utf-8", errors="strict")
    if "\r" in data or "\x00" in data:
        raise ValueError("config_source_invalid_encoding")
    lines = data.splitlines(keepends=True)
    if line > len(lines):
        raise ValueError("config_error_line_out_of_bounds")
    replacement = _repair_line(lines[line - 1], error)
    if replacement is None:
        raise ValueError("config_change_not_deterministic")
    lines[line - 1] = replacement
    candidate = "".join(lines).encode("utf-8")
    if hashlib.sha256(candidate).hexdigest() != candidate_sha256:
        raise ValueError("config_candidate_hash_mismatch")
    return candidate.decode("utf-8")


def rebuild_json_candidate(*, encoded: str, path: str,
                           original_sha256: str, candidate_sha256: str) -> str:
    """Rebuild an immutable one-comma JSON fix; syntax-only, not app health."""
    if not checked_config_path(path).endswith(".json"):
        raise ValueError("config_format_not_supported")
    if not all(re.fullmatch(r"[0-9a-f]{64}", h or "") for h in (original_sha256, candidate_sha256)):
        raise ValueError("config_candidate_invalid_contract")
    source = base64.b64decode(encoded, validate=True)
    if not 1 <= len(source) <= 262144 or hashlib.sha256(source).hexdigest() != original_sha256:
        raise ValueError("config_source_hash_drift")
    contents = source.decode("utf-8", errors="strict")
    if "\x00" in contents:
        raise ValueError("config_source_invalid_encoding")
    try:
        json.loads(contents)
    except json.JSONDecodeError:
        pass
    else:
        raise ValueError("source_json_already_valid")
    candidate = _remove_trailing_json_commas(contents)
    if not candidate or contents.count(",") - candidate.count(",") != 1:
        raise ValueError("config_change_not_deterministic")
    json.loads(candidate)
    if hashlib.sha256(candidate.encode("utf-8")).hexdigest() != candidate_sha256:
        raise ValueError("config_candidate_hash_mismatch")
    return candidate


def rebuild_xml_candidate(*, encoded: str, path: str,
                          original_sha256: str, candidate_sha256: str) -> str:
    """Remove one unmatched EOF closing tag; never edit XML values or DTDs."""
    if not checked_config_path(path).endswith(".xml"):
        raise ValueError("config_format_not_supported")
    if not all(re.fullmatch(r"[0-9a-f]{64}", h or "") for h in (original_sha256, candidate_sha256)):
        raise ValueError("config_candidate_invalid_contract")
    raw = base64.b64decode(encoded, validate=True)
    if not 1 <= len(raw) <= 262144 or hashlib.sha256(raw).hexdigest() != original_sha256:
        raise ValueError("config_source_hash_drift")
    source = raw.decode("utf-8", errors="strict")
    if "\x00" in source or "<!DOCTYPE" in source.upper() or "<!ENTITY" in source.upper():
        raise ValueError("xml_unsafe_entities_or_encoding")
    try:
        ET.fromstring(source)
    except ET.ParseError:
        pass
    else:
        raise ValueError("source_xml_already_valid")
    match = re.search(r"</[A-Za-z][A-Za-z0-9_.:-]{0,47}>(?=\s*\Z)", source)
    if not match:
        raise ValueError("config_change_not_deterministic")
    candidate = source[:match.start()] + source[match.end():]
    ET.fromstring(candidate)
    if hashlib.sha256(candidate.encode("utf-8")).hexdigest() != candidate_sha256:
        raise ValueError("config_candidate_hash_mismatch")
    return candidate



# Root-helper exit statuses are intentionally stable and content-free. Neither
# stderr nor raw program output is allowed into an incident, audit log or LLM.
_GUARD_FAILURE_CODES = {
    41: "config_guard_request_rejected",
    42: "config_guard_prerequisite_failed",
    43: "config_guard_candidate_hash_mismatch",
    44: "config_guard_lock_or_replay_blocked",
    45: "config_guard_source_hash_changed",
    46: "config_guard_staging_failed",
    47: "config_guard_vendor_syntax_failed",
    50: "config_guard_mount_namespace_unavailable",
    51: "config_guard_isolated_mount_failed",
}


def classify_config_guard_failure(observed: dict) -> str:
    """Use only fixed, operator-actionable codes; never reflect stderr."""
    if observed.get("error") == "ssh_command_timeout":
        return "config_guard_ssh_timeout"
    if observed.get("error") == "ssh_command_failed":
        return "config_guard_ssh_connection_failed"
    code = observed.get("exit_code")
    if type(code) is int and code in _GUARD_FAILURE_CODES:
        return _GUARD_FAILURE_CODES[code]
    stderr = str(observed.get("stderr") or "").lower()
    if ("a password is required" in stderr
            or "no tty present and no askpass program specified" in stderr
            or "a terminal is required to read the password" in stderr):
        return "config_guard_sudo_nopasswd_required"
    if ("not in the sudoers file" in stderr or "not allowed to execute" in stderr
            or "is not allowed to run sudo" in stderr or "may not run sudo" in stderr):
        return "config_guard_sudo_policy_denied"
    if "command not found" in stderr or "no such file or directory" in stderr:
        # A missing dependency or helper interpreter is not evidence that
        # /usr/local/sbin/aiops-config-guard itself does not exist.
        return ("config_guard_helper_missing"
                if "/usr/local/sbin/aiops-config-guard" in stderr
                else "config_guard_execution_failed")
    if "permission denied" in stderr:
        return "config_guard_helper_permission_denied"
    if code == 1:
        # Plain rc=1 cannot distinguish sudo policy, stdin I/O or helper
        # execution. Never misreport it as invalid vendor syntax.
        return "config_guard_sudo_or_invocation_failed"
    return "config_guard_execution_failed"


async def run_governed_change(connector, *, action: str, target: str, service: str,
                              config_file: str, original_sha256: str,
                              candidate_sha256: str, proposed_change: str,
                              execution_claims: dict | None = None,
                              execution_signature: str | None = None) -> dict:
    if action not in {"validate", "apply"}:
        raise PermissionError("config_action_not_allowed")
    connector._validate_target(target)
    connector._validate_service(service)
    name = str(service).lower().removesuffix(".service")
    # An apply call MUST itself verify the original HMAC, not only trust
    # the MCP route to have verified it earlier. This is a privileged
    # in-memory script boundary rather than a root-owned on-host verifier.
    if action == "apply":
        verify_claim(execution_claims, execution_signature,
                     target=target, service=service)
        expected = {
            "config_file": config_file,
            "original_sha256": original_sha256,
            "candidate_sha256": candidate_sha256,
            "proposed_change": proposed_change,
        }
        if any(execution_claims.get(k) != v for k, v in expected.items()):
            raise PermissionError("config_execution_claim_binding_changed")
    nginx_profile = name == "nginx" and proposed_change == "remove_extra_opening_brace"
    json_profile = proposed_change == "remove_trailing_json_comma"
    xml_profile = proposed_change == "remove_extra_xml_closing_tag"
    if not (nginx_profile or json_profile or xml_profile):
        return {"success": False, "status": "unsupported_vendor_apply_adapter",
                "isolated_validation": False, "production_write_performed": False}
    try:
        path = _checked_path(config_file) if nginx_profile else checked_config_path(config_file)
        if json_profile and not path.endswith(".json"):
            raise ValueError("config_file_type_mismatch")
        if xml_profile and not path.endswith(".xml"):
            raise ValueError("config_file_type_mismatch")
    except ValueError:
        return {"success": False, "status": "config_path_not_allowlisted",
                "isolated_validation": False, "production_write_performed": False}
    try:
        if nginx_profile:
            # Re-observe the exact nginx compiler failure and source hash.
            diagnostic = await connector.config_validate(target, service)
            if not (diagnostic.get("success") is True and diagnostic.get("supported") is True
                    and diagnostic.get("valid") is False and diagnostic.get("config_file") == path
                    and type(diagnostic.get("error_line")) is int):
                return {"success": False, "status": "fresh_vendor_diagnostic_mismatch",
                        "isolated_validation": False, "production_write_performed": False}
            line = diagnostic["error_line"]
            error = str(diagnostic.get("syntax_error") or diagnostic.get("detail") or "")
            if not re.search(r'unexpected\s+["“]?\{', error, re.I):
                return {"success": False, "status": "vendor_error_changed",
                        "isolated_validation": False, "production_write_performed": False}
            read = await connector._run(target, nginx_review_command(path, line, error))
            if read.get("success") is not True:
                raise ValueError("config_live_file_read_failed")
            candidate = rebuild_nginx_candidate(
                encoded=str(read.get("stdout") or ""), path=path, line=line,
                error=error, original_sha256=original_sha256,
                candidate_sha256=candidate_sha256)
        else:
            # The file MUST be rediscovered on the same service through the
            # VM's read-only, systemd-derived inventory. LLM paths are advisory.
            observed = await connector.service_config_discovery(target, service)
            files = observed.get("files") or []
            bound = observed.get("success") is True and any(
                isinstance(x, dict) and x.get("path") == path
                and x.get("verified_exists") is True
                for x in files
            )
            if not bound:
                return {"success": False, "status": "config_path_not_bound_to_service",
                        "isolated_validation": False, "production_write_performed": False}
            read = await connector._run(target, remote_config_read_command(path))
            if read.get("success") is not True:
                raise ValueError("config_live_file_read_failed")
            rebuild = rebuild_json_candidate if json_profile else rebuild_xml_candidate
            candidate = rebuild(
                encoded=str(read.get("stdout") or ""), path=path,
                original_sha256=original_sha256, candidate_sha256=candidate_sha256,
            )
    except (ValueError, UnicodeError, OSError, json.JSONDecodeError, ET.ParseError):
        return {"success": False, "status": "live_source_or_candidate_drift",
                "isolated_validation": False, "production_write_performed": False}
    profile = "nginx" if nginx_profile else name
    scope = ("nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies"
             if nginx_profile else "generic_json_syntax_only_service_runtime_unverified"
             if json_profile else "generic_xml_syntax_only_service_runtime_unverified")
    validator = ("nginx -t (private mount namespace)" if nginx_profile
                 else "jq empty (JSON syntax only; application semantics unverified)"
                 if json_profile else "xmllint --nonet --noout (XML syntax only)")

    # The only executable material is our versioned, fixed POSIX program.
    # It travels over encrypted SSH stdin with the hash-bound candidate;
    # no VM-side helper, Python, deploy step or LLM-built root command.
    # A sudo-capable SSH identity is required, just as when the operator
    # manually uses sudo/su. Only this fixed command is generated.
    try:
        command, script = build_ephemeral_guard(
            action=action,
            profile=("nginx" if nginx_profile else "json_syntax" if json_profile
                     else "xml_syntax"),
            path=path, original_sha256=original_sha256,
            candidate_sha256=candidate_sha256, candidate=candidate,
            approval_id=execution_claims["approval_id"] if action == "apply" else None,
        )
    except ValueError:
        return {"success": False, "status": "config_guard_request_rejected",
                "isolated_validation": False, "production_write_performed": False}
    logger.info(
        "vm_config_ephemeral_transaction_started",
        target=target, service=name, action=action,
        candidate_bytes=len(candidate.encode("utf-8")),
        isolated_validation_requested=True,
        production_write_requested=action == "apply",
    )
    observed = await connector._sudo(target, command, stdin_data=script)
    output = str(observed.get("stdout") or "")
    if action == "validate":
        success = observed.get("success") is True and output == "VALIDATED"
        result_status = ("isolated_vendor_validation_passed" if success
                         else classify_config_guard_failure(observed))
        guard_exit_code = (observed.get("exit_code")
                           if type(observed.get("exit_code")) is int else None)
        logger.info(
            "vm_config_guard_validation_completed",
            target=target, service=name, phase="isolated_vendor_check",
            result=result_status, guard_exit_code=guard_exit_code,
            isolated_validation=success, production_write_performed=False,
        )
        return {
            "success": success,
            "status": result_status,
            "guard_exit_code": guard_exit_code,
            "isolated_validation": success,
            "validation_scope": scope,
            "vendor_validator": validator,
            "original_sha256": original_sha256, "candidate_sha256": candidate_sha256,
            "production_write_performed": False,
            "remote_python_required": False,
        }

    applied = observed.get("success") is True and output == "APPLIED_VERIFIED"
    rolled_back = output == "ROLLED_BACK"
    # Only bounded enum values/exit code; do not log the signed claim,
    # candidate bytes, validator stderr or the sudo password.
    result_status = ("applied_verified" if applied else "rolled_back"
                     if rolled_back else "rollback_failed"
                     if output == "ROLLBACK_FAILED" else "apply_failed_or_blocked")
    logger.info(
        "vm_config_guard_apply_completed",
        target=target, service=name, phase="approved_apply",
        result=result_status, guard_exit_code=observed.get("exit_code"),
        production_write_performed=applied or rolled_back or output == "ROLLBACK_FAILED",
    )
    recovery = {"attempted": False, "status": "not_authorized",
                "service_recovery_confirmed": False}
    if applied and execution_claims.get("recovery_action") == "start_service":
        recovery = await _start_after_approved_config_apply(
            connector, target=target, service=service)
    # The trusted ephemeral POSIX program performs source-CAS, backup, atomic
    # replacement, post-write validation and rollback on a bad candidate.
    return {
        "service_recovery": recovery,
        "service_recovery_confirmed": recovery["service_recovery_confirmed"],
        "success": applied,
        "status": result_status,
        "isolated_validation": applied,
        "validation_scope": scope,
        "original_sha256": original_sha256, "candidate_sha256": candidate_sha256,
        "production_write_performed": applied or rolled_back or output == "ROLLBACK_FAILED",
        "rollback_status": ("not_required" if applied else "restored_original"
                            if rolled_back else "unverified"),
        "remote_python_required": False,
    }


async def _start_after_approved_config_apply(connector, *, target: str, service: str) -> dict:
    """Only the signed approval recovery scope authorizes a single systemd start.

    This never closes an incident without authoritative monitor recovery.
    """
    unavailable = {"attempted": False, "status": "precheck_unavailable",
                   "service_recovery_confirmed": False}
    try:
        before = await connector.service_status(target, service)
        if before.get("success") is not True:
            return unavailable
        if before.get("active_state") == "active":
            return {"attempted": False, "status": "already_active",
                    "service_recovery_confirmed": True}
        if (before.get("active_state") not in {"failed", "inactive"}
                or before.get("load_state") != "loaded"):
            return {"attempted": False, "status": "service_state_not_startable",
                    "service_recovery_confirmed": False}
        started = await connector.start_service(target, service)
        if started.get("success") is not True:
            return {"attempted": True, "status": "start_failed",
                    "service_recovery_confirmed": False}
        after = await connector.service_status(target, service)
        confirmed = (after.get("success") is True
                     and after.get("active_state") == "active"
                     and after.get("healthy") is True)
        status = "systemd_active" if confirmed else "start_not_verified"
        logger.info("vm_config_recovery_checked", target=target, service=service,
                    status=status, started=True, systemd_active=confirmed)
        return {"attempted": True, "status": status,
                "service_recovery_confirmed": confirmed}
    except Exception:
        logger.warning("vm_config_recovery_check_failed", target=target, service=service)
        return unavailable
