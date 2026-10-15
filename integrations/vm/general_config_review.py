"""Secret-safe, non-mutating configuration review on the trusted VM MCP worker.

Paths must originate from a verified systemd/validator observation, NEVER from
LLM text. The file bytes are bounded, transferred over authenticated SSH and
only decoded within the VM MCP process. No complete config, key/value, XML
attribute, classpath or connection string is ever returned/persisted.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import shlex
import xml.etree.ElementTree as ET

from integrations.vm.runtime_discovery import _candidate_path

_MAX = 262_144
_ROOTS = ("/etc/", "/opt/", "/srv/", "/data/", "/usr/local/etc/", "/usr/local/tomcat/")
_REJECT = ("/etc/shadow", "/etc/ssh/", "/etc/ssl/", "/etc/pki/", "/etc/security/",
           "/opt/secrets/", "/run/", "/proc/", "/sys/", "/dev/")
_REVIEW_EXT = (".xml", ".json", ".properties", ".yaml", ".yml", ".cfg", ".conf", ".ini")


def checked_config_path(path: str) -> str:
    safe = _candidate_path(path)
    if (not safe or not safe.startswith(_ROOTS) or safe.startswith(_REJECT)
            or not safe.endswith(_REVIEW_EXT)):
        raise ValueError("unsafe_configuration_path")
    return safe


def remote_config_read_command(path: str) -> str:
    """Fixed coreutils only; not a general-purpose remote file-read API."""
    safe = checked_config_path(path)
    q = shlex.quote(safe)
    return (
        "test -f " + q + " && test -r " + q + " && test ! -L " + q
        + " && test \"$(readlink -f -- " + q + ")\" = " + q
        + " && n=$(LC_ALL=C stat -c %s -- " + q + ")"
        + " && test \"$n\" -ge 1 && test \"$n\" -le " + str(_MAX)
        + " && LC_ALL=C head -c " + str(_MAX + 1) + " -- " + q
        + " | base64 -w 0"
    )


def _structural_line(value: str) -> str:
    trimmed = value.strip()
    if not trimmed or trimmed.startswith(("#", ";", "//", "<!--")):
        return "[blank or comment]"
    if trimmed.startswith("<"):
        match = re.match(r"</?([A-Za-z][A-Za-z0-9_.:-]{0,50})", trimmed)
        known_tags = {
            "server", "service", "connector", "engine", "host", "context",
            "listener", "realm", "valve", "resource", "manager",
        }
        safe_tag = match.group(1) if match and match.group(1).lower() in known_tags else "unknown"
        return "xml_tag:" + safe_tag + (
            ":closing" if trimmed.startswith("</") else ":opening"
        )
    # Never echo arbitrary property names or YAML keys: some deployments use
    # credential identifiers as keys. Expose only a tiny vendor directive set.
    word = re.match(r"[A-Za-z_][A-Za-z0-9_-]{0,50}", trimmed)
    allowed = {"global", "defaults", "frontend", "backend", "listen",
               "bind", "server", "mode", "timeout", "option", "acl", "use_backend"}
    return "directive:" + word.group(0) if word and word.group(0) in allowed else "structural_line"


def _remove_trailing_json_commas(source: str) -> str:
    """Only a lexical trailing comma outside JSON strings; never change values."""
    chars = list(source)
    in_string = False
    escaped = False
    erase = []
    for i, ch in enumerate(chars):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == ",":
            k = i + 1
            while k < len(chars) and chars[k] in " \t\r\n":
                k += 1
            if k < len(chars) and chars[k] in "]}":
                erase.append(i)
    for i in erase:
        chars[i] = ""
    return "".join(chars)


def local_config_review(encoded: str, *, path: str, validator_error_line: int | None = None) -> dict:
    """Review a known config source and generate only a deterministic JSON fix."""
    checked_config_path(path)
    answer = {
        "success": True, "status": "unavailable", "config_file": path,
        "file_type": path.rsplit(".", 1)[-1].lower(),
        "validation_status": "UNVERIFIED", "source_hash": None,
        "candidate_hash": None, "proposed_change": None,
        "redacted_diff": None, "current_excerpt": [],
        "proposed_excerpt": [], "validator_executed_on_proposal": False,
        "test_scope": "worker_format_validation_only",
        "remote_python_required": False, "config_contents_exposed": False,
        "execution_authority": False, "apply_eligible": False,
    }
    if not isinstance(encoded, str) or len(encoded) > ((_MAX + 2) // 3) * 4 + 16:
        return answer
    try:
        contents = base64.b64decode(encoded, validate=True)
        if not 1 <= len(contents) <= _MAX:
            return answer
        source = contents.decode("utf-8", errors="strict")
        if "\x00" in source:
            return answer
    except (ValueError, UnicodeError, binascii.Error):
        return answer
    answer["source_hash"] = hashlib.sha256(contents).hexdigest()
    lines = source.splitlines()
    answer["status"] = "file_observed"
    line_no = validator_error_line if type(validator_error_line) is int else None
    ext = answer["file_type"]
    error = None
    if ext == "json":
        try:
            json.loads(source)
            answer["validation_status"] = "FORMAT_VALID"
        except json.JSONDecodeError as exc:
            line_no = exc.lineno
            answer["validation_status"] = "FORMAT_INVALID"
            error = "json_syntax_error"
            updated = _remove_trailing_json_commas(source)
            # One displayed redacted diff must correspond to one real edit.
            # Reject multi-edit previews until the UI can show every changed line.
            if updated != source and source.count(",") - updated.count(",") == 1:
                try:
                    json.loads(updated)
                except (ValueError, TypeError):
                    pass
                else:
                    answer.update({
                        "status": "candidate_proposed",
                        "candidate_hash": hashlib.sha256(updated.encode("utf-8")).hexdigest(),
                        "proposed_change": "remove_trailing_json_comma",
                        "validator_executed_on_proposal": True,
                        "candidate_validator": "worker_python_json_syntax",
                        "validation_status": "FORMAT_CANDIDATE_VALID_ONLY",
                        "redacted_diff": {"line": line_no, "before": "json_trailing_comma",
                                          "after": "json_comma_removed"},
                    })
    elif ext == "xml":
        if "<!DOCTYPE" in source.upper() or "<!ENTITY" in source.upper():
            error = "xml_dtd_or_entity_not_allowed"
            answer["validation_status"] = "FORMAT_UNVERIFIED"
        else:
            try:
                ET.fromstring(source)
                answer["validation_status"] = "FORMAT_VALID"
            except ET.ParseError as exc:
                line_no = exc.position[0]
                error = "xml_syntax_error"
                answer["validation_status"] = "FORMAT_INVALID"
                # One extra, unmatched *closing* tag at EOF is the only
                # supported XML transformation. Never invent attributes,
                # values, namespaces, or missing elements with an LLM.
                closing = re.search(
                    r"</[A-Za-z][A-Za-z0-9_.:-]{0,47}>(?=\s*\Z)", source
                )
                if closing:
                    proposed = source[:closing.start()] + source[closing.end():]
                    try:
                        ET.fromstring(proposed)
                    except ET.ParseError:
                        pass
                    else:
                        line_no = source[:closing.start()].count("\n") + 1
                        answer.update({
                            "status": "candidate_proposed",
                            "candidate_hash": hashlib.sha256(proposed.encode("utf-8")).hexdigest(),
                            "proposed_change": "remove_extra_xml_closing_tag",
                            "validator_executed_on_proposal": True,
                            "candidate_validator": "worker_python_xml_syntax",
                            "validation_status": "FORMAT_CANDIDATE_VALID_ONLY",
                            "redacted_diff": {
                                "line": line_no, "before": "xml_extra_closing_tag",
                                "after": "xml_closing_tag_removed",
                            },
                        })
    # YAML/HAProxy/properties are intentionally NOT "syntax valid" based on
    # looking at source bytes. Only their registered vendor validators may
    # establish correctness; do not synthesize a patch for them.
    answer["error_category"] = error
    answer["observed_error_line"] = line_no
    if type(line_no) is int and 1 <= line_no <= len(lines):
        start = max(0, line_no - 4)
        answer["current_excerpt"] = [
            {"line": i + 1, "content": _structural_line(lines[i])}
            for i in range(start, min(len(lines), line_no + 3))
        ]
    if answer["status"] == "candidate_proposed":
        answer["proposed_excerpt"] = [
            {"line": line_no, "content": (
                "xml_closing_tag_removed" if ext == "xml" else "json_comma_removed"
            )}
        ]
    return answer
