"""Read-only Nginx repair preview computed on the AIOps VM MCP worker.

Target host requires only stock POSIX shell and Linux coreutils (readlink,
stat, head, base64). The authenticated SSH transport transfers a bounded file
in memory to the trusted VM MCP worker. The original bytes MUST NEVER reach
tool results, logs, audit, database, web or an LLM. No file is written and no
candidate validation or production action is claimed by this module.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import shlex

from integrations.vm.service_adapters import _absolute_config_path

_ALLOWED_ROOTS = ("/etc/nginx/", "/usr/local/nginx/conf/")
_MAX_BYTES = 262_144
_MAX_B64_LEN = ((_MAX_BYTES + 2) // 3) * 4 + 16
_BLOCKS = ("server", "http", "events", "stream", "upstream",
           "location", "map", "types")


def _checked_path(path: str) -> str:
    safe = _absolute_config_path(path)
    if not safe or not safe.startswith(_ALLOWED_ROOTS) or len(safe) > 240:
        raise ValueError("nginx_config_path_not_allowed")
    return safe


def nginx_review_command(path: str, line: int, syntax_error: str) -> str:
    """Fixed read-only remote command; never invokes remote Python or writes.

    Paths and error line originate exclusively from current nginx -t output.
    Recheck all parents for symlinks on the target and refuse overlarge files.
    No arbitrary path, filename or LLM command is accepted.
    """
    checked = _checked_path(path)
    if type(line) is not int or not 1 <= line <= 100_000:
        raise ValueError("nginx_error_line_not_valid")
    if not isinstance(syntax_error, str):
        raise ValueError("nginx_error_not_valid")
    q = shlex.quote(checked)
    # Exact file path only, no following symlinks (including ancestors).
    return (
        "test -f " + q + " && test -r " + q + " && test ! -L " + q
        + " && test \"$(readlink -f -- " + q + ")\" = " + q
        + " && n=$(LC_ALL=C stat -c %s -- " + q + ")"
        + " && test \"$n\" -ge 1 && test \"$n\" -le " + str(_MAX_BYTES)
        + " && LC_ALL=C head -c " + str(_MAX_BYTES + 1)
        + " -- " + q + " | base64 -w 0"
    )


def _visible_line(value: str) -> str:
    """Whitelist directive name and structural braces; never output values."""
    stripped = value.strip()
    if not stripped or stripped.startswith("#"):
        return "[blank or comment]"
    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", stripped)
    name = m.group(1)[:40] if m else "[structural]"
    braces = "".join(ch for ch in stripped if ch in "{}")[:8]
    return name + (" [arguments redacted]" if m else "") + (
        " " + braces if braces else ""
    )


def _repair_line(line: str, error: str) -> str | None:
    if not re.search(r'unexpected\s+["\u201c]?\{', error, re.I):
        return None
    if line.strip() == "{":
        return ""
    # Whitelisted block names + a trivially duplicated opening brace only.
    # Arbitrary LLM edits, includes, values and multiline transformations
    # can never be used to construct a candidate.
    names = "|".join(_BLOCKS)
    m = re.fullmatch(
        rf"([ \t]*(?:{names})(?:[ \t]+[^{{}}#\r\n]+)?[ \t]*\{{)"
        r"[ \t]*\{[ \t]*(?:\n)?", line
    )
    return m.group(1) + ("\n" if line.endswith("\n") else "") if m else None


def local_nginx_review(
    *, encoded: str, file_path: str, error_line: int, syntax_error: str,
) -> dict:
    """Bounded local-only deterministic preview. Never expose original bytes."""
    _checked_path(file_path)
    if type(error_line) is not int or not 1 <= error_line <= 100_000:
        raise ValueError("nginx_error_line_not_valid")
    result = {
        "status": "unavailable", "validation_status": "UNVERIFIED",
        "stage_failure_reason": "isolated_validation_not_available",
        "test_scope": "worker_preview_unvalidated",
        "validator_executed_on_proposal": False,
        "current_hash": None, "candidate_hash": None,
        "current_excerpt": [], "proposed_excerpt": [],
        "diff": None, "proposed_change": None,
        "execution_authority": False, "config_contents_exposed": False,
        "remote_python_required": False,
    }
    if not isinstance(encoded, str) or len(encoded) > _MAX_B64_LEN:
        return result
    try:
        original = base64.b64decode(encoded, validate=True)
        if not 1 <= len(original) <= _MAX_BYTES:
            return result
        original_text = original.decode("utf-8", errors="strict")
        if "\r" in original_text or "\x00" in original_text:
            return result
    except (ValueError, UnicodeError, binascii.Error):
        return result
    lines = original_text.splitlines(keepends=True)
    if not 1 <= error_line <= len(lines):
        return result
    line = lines[error_line - 1]
    start, end = max(0, error_line - 4), min(len(lines), error_line + 3)
    result["current_hash"] = hashlib.sha256(original).hexdigest()
    result["current_excerpt"] = [
        {"line": i + 1, "content": _visible_line(lines[i])}
        for i in range(start, end)
    ]
    result["status"] = "observed"
    replacement = _repair_line(line, syntax_error)
    if replacement is None:
        return result
    fixed_lines = list(lines)
    fixed_lines[error_line - 1] = replacement
    candidate = "".join(fixed_lines).encode("utf-8")
    result.update({
        "status": "candidate_proposed",
        "candidate_hash": hashlib.sha256(candidate).hexdigest(),
        "proposed_change": "remove_extra_opening_brace",
        "proposed_excerpt": [
            {"line": i + 1, "content": _visible_line(fixed_lines[i])}
            for i in range(start, end)
        ],
        "diff": {
            "line": error_line, "before": _visible_line(line),
            "after": _visible_line(replacement) if replacement
                     else "[remove entire stray brace line]",
            "redacted": True,
        },
    })
    return result
