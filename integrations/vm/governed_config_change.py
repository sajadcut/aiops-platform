"""Trusted VM MCP worker for bounded hash-bound configuration operations.

Full source and candidate bytes stay in this process and SSH stdin. Neither
payload is returned to API, LLM, audit, checkpoints, or browser.
"""
from __future__ import annotations
import base64
import hashlib
import re
import shlex

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


async def run_governed_change(connector, *, action: str, target: str, service: str,
                              config_file: str, original_sha256: str,
                              candidate_sha256: str, proposed_change: str,
                              execution_claims: dict | None = None) -> dict:
    if action not in {"validate", "apply"}:
        raise PermissionError("config_action_not_allowed")
    connector._validate_target(target)
    connector._validate_service(service)
    if str(service).lower().removesuffix(".service") != "nginx" or proposed_change != "remove_extra_opening_brace":
        return {"success": False, "status": "unsupported_vendor_apply_adapter",
                "isolated_validation": False, "production_write_performed": False}
    try:
        path = _checked_path(config_file)
    except ValueError:
        return {"success": False, "status": "config_path_not_allowlisted",
                "isolated_validation": False, "production_write_performed": False}

    # Re-observe the live compiler diagnostic, including its file and line.
    diagnostic = await connector.config_validate(target, service)
    if not (diagnostic.get("success") is True
            and diagnostic.get("supported") is True
            and diagnostic.get("valid") is False
            and diagnostic.get("config_file") == path
            and type(diagnostic.get("error_line")) is int):
        return {"success": False, "status": "fresh_vendor_diagnostic_mismatch",
                "isolated_validation": False, "production_write_performed": False}
    line = diagnostic["error_line"]
    error = str(diagnostic.get("syntax_error") or diagnostic.get("detail") or "")
    if not re.search(r'unexpected\s+["“]?\{', error, re.I):
        return {"success": False, "status": "vendor_error_changed",
                "isolated_validation": False, "production_write_performed": False}
    try:
        read = await connector._run(target, nginx_review_command(path, line, error))
        if read.get("success") is not True:
            raise ValueError("config_live_file_read_failed")
        candidate = rebuild_nginx_candidate(
            encoded=str(read.get("stdout") or ""), path=path, line=line,
            error=error, original_sha256=original_sha256,
            candidate_sha256=candidate_sha256,
        )
    except (ValueError, UnicodeError, OSError):
        return {"success": False, "status": "live_source_or_candidate_drift",
                "isolated_validation": False, "production_write_performed": False}

    # No unrestricted SSH root command: sudoers may delegate only the pre-
    # provisioned, root-owned guard. Never send config bytes in argv or logs.
    arguments = [action, "nginx", path, original_sha256, candidate_sha256]
    if action == "apply":
        if not execution_claims:
            raise PermissionError("root_config_guard_requires_signed_claim")
        from apps.config_change_authorization import sign_root_guard
        arguments += [
            execution_claims["approval_id"], execution_claims["incident_id"],
            execution_claims["target"], str(execution_claims["expires"]),
            sign_root_guard(execution_claims),
        ]
    command = "sudo -n /usr/local/sbin/aiops-config-guard " + " ".join(
        shlex.quote(part) for part in arguments
    )
    observed = await connector._run(target, command, stdin_data=candidate)
    output = str(observed.get("stdout") or "")
    if action == "validate":
        success = observed.get("success") is True and output == "VALIDATED"
        return {
            "success": success,
            "status": "isolated_vendor_validation_passed" if success else "isolated_vendor_validation_failed",
            "isolated_validation": success,
            "validation_scope": "nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies",
            "vendor_validator": "nginx -t (private mount namespace)",
            "original_sha256": original_sha256, "candidate_sha256": candidate_sha256,
            "production_write_performed": False,
            "remote_python_required": False,
        }

    applied = observed.get("success") is True and output == "APPLIED_VERIFIED"
    rolled_back = output == "ROLLED_BACK"
    # The fixed remote helper performs source-CAS, backup, atomic rename,
    # post-write vendor validation and immediate rollback on a bad candidate.
    return {
        "success": applied,
        "status": ("applied_verified" if applied else
                   "rolled_back" if rolled_back else
                   "rollback_failed" if output == "ROLLBACK_FAILED" else
                   "apply_failed_or_blocked"),
        "isolated_validation": applied,
        "validation_scope": "nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies",
        "original_sha256": original_sha256, "candidate_sha256": candidate_sha256,
        "production_write_performed": applied or rolled_back or output == "ROLLBACK_FAILED",
        "rollback_status": ("not_required" if applied else "restored_original"
                            if rolled_back else "unverified"),
        "remote_python_required": False,
    }
