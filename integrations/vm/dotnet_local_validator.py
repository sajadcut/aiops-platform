"""Validate .NET appsettings JSON on the AIOps worker, not on customer VMs.

Only limited read-only file bytes are fetched over authenticated SSH from the
publish directory discovered in the systemd unit. File contents and JSON keys
or values must NEVER be returned, logged, persisted, or sent to an LLM.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import shlex
from typing import Any

from integrations.vm.runtime_discovery import safe_absolute_path

MAX_FILE_BYTES = 1_048_576
MAX_FILES = 12
_NAME = re.compile(
    # Config inventory is bound to the systemd publish directory. Syntax
    # validation never returns file contents, keys, values or secret data.
    # Exclude hidden and credential files, but inspect ordinary service JSON.
    r"(?!.*(?:secret|password|credential|private|\.key))"
    r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,99}\.json\Z", re.I,
)

# Neither error messages nor excerpts include JSON values, secret names,
# provider endpoints, passwords or any part of the source line.
_MESSAGES = {
    "Expecting property name enclosed in double quotes": (
        "json_property_name", "نام کلید باید داخل کوتیشن دوتایی باشد؛ ویرگول اضافهٔ خط قبل را نیز بررسی کنید."
    ),
    "Expecting value": ("json_value_missing", "مقدار JSON وجود ندارد یا ناقص است؛ ویرگول یا مقدار کنار محل خطا را بررسی کنید."),
    "Expecting ',' delimiter": ("json_comma_expected", "جداکنندهٔ ویرگول یا ساختار عبارت قبل از محل خطا نادرست است."),
    "Expecting ':' delimiter": ("json_colon_expected", "بین نام کلید و مقدار باید دونقطه (:) باشد."),
    "Extra data": ("json_extra_data", "بعد از پایان ساختار JSON، دادهٔ اضافی وجود دارد."),
    "Unterminated string starting at": ("json_unterminated_string", "رشتهٔ متنی بسته نشده است؛ کوتیشن پایانی را بررسی کنید."),
    "Invalid \\escape": ("json_invalid_escape", "کاراکتر Escape نامعتبر داخل رشته وجود دارد."),
    "Invalid control character at": ("json_control_character", "کاراکتر کنترل غیرمجاز داخل رشته وجود دارد."),
    "Expecting ',' delimiter": ("json_comma_expected", "ساختار قبل از محل خطا به ویرگول نیاز دارد."),
}


def safe_json_files(output: str) -> tuple[list[str], bool]:
    """Parse untrusted remote directory names. Excess is NOT a full validation."""
    records = sorted(set(str(output or "").splitlines()))
    if len(records) > 500 or any(len(row) > 200 for row in records):
        return [], True
    allowed = []
    incomplete = False
    for item in records:
        name, tab, file_type = item.partition("\t")
        if not tab or len(file_type) != 1:
            return [], True
        if _NAME.fullmatch(name):
            if file_type == "f":
                allowed.append(name)
            else:
                incomplete = True
    return allowed[:MAX_FILES], incomplete or len(allowed) > MAX_FILES


def remote_file_listing_command(publish: str) -> str:
    directory = safe_absolute_path(publish)
    if not directory or len(directory.split("/")) < 3:
        raise ValueError("unsafe_dotnet_publish_directory")
    if directory.startswith(("/proc/", "/sys/", "/dev/", "/etc/")):
        raise ValueError("unsafe_dotnet_publish_directory")
    quoted = shlex.quote(directory)
    return (
        "test -d " + quoted + " && test ! -L " + quoted
        + " && test \"$(readlink -f -- " + quoted + ")\" = " + quoted
        + " && LC_ALL=C find " + quoted
        + " -mindepth 1 -maxdepth 1 -printf '%f\\t%y\\n' 2>/dev/null"
    )


def remote_file_read_command(publish: str, filename: str) -> str:
    directory = safe_absolute_path(publish)
    if not directory or len(directory.split("/")) < 3 or not _NAME.fullmatch(filename):
        raise ValueError("unsafe_dotnet_config_filename")
    path = safe_absolute_path(directory + "/" + filename)
    if not path:
        raise ValueError("unsafe_dotnet_config_path")
    quoted = shlex.quote(path)
    root = shlex.quote(directory)
    # POSIX shell syntax and ubiquitous coreutils only; not python, jq,
    # dotnet SDK or npm on the target VM. 1 MiB upper bound per file.
    return (
        "test -f " + quoted + " && test ! -L " + quoted
        + " && test -d " + root + " && test ! -L " + root
        + " && test \"$(readlink -f -- " + root + ")\" = " + root
        + " && n=$(LC_ALL=C stat -c %s -- " + quoted + ")"
        + " && test \"$n\" -le " + str(MAX_FILE_BYTES)
        + " && LC_ALL=C head -c " + str(MAX_FILE_BYTES + 1)
        + " -- " + quoted + " | base64 -w 0"
    )


class DotnetJsonCommentError(ValueError):
    def __init__(self, source: str, index: int):
        self.line = source.count("\n", 0, index) + 1
        self.column = index - source.rfind("\n", 0, index)
        super().__init__("unclosed_json_comment")


def normalize_dotnet_json(source: str) -> str:
    """Ignore JSON comments and trailing commas accepted by .NET configuration.

    Replace syntax-only portions with whitespace of identical length so Python
    JSONDecodeError line and column still refer to the actual original file.
    Quoted strings, escapes, values, secret material and keys are NOT modified.
    """
    chars = list(source)
    i, quoted, escaped = 0, False, False
    while i < len(chars):
        ch = chars[i]
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            i += 1
            continue
        if ch == '"':
            quoted = True
            i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "/":
            while i < len(chars) and chars[i] not in "\r\n":
                chars[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "*":
            begin = i
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            found_end = False
            while i < len(chars):
                if i + 1 < len(chars) and chars[i] == "*" and chars[i + 1] == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    found_end = True
                    break
                if chars[i] not in "\r\n":
                    chars[i] = " "
                i += 1
            if not found_end:
                raise DotnetJsonCommentError(source, begin)
            continue
        i += 1
    # Find trailing commas, again respecting string literals.
    i, quoted, escaped = 0, False, False
    while i < len(chars):
        ch = chars[i]
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch == ",":
            j = i + 1
            while j < len(chars) and chars[j].isspace():
                j += 1
            if j < len(chars) and chars[j] in "]}":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _reject_constant(_value: str) -> None:
    raise ValueError("nonstandard_json_constant")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def validate_encoded_file(filename: str, encoded: str) -> dict:
    """Parse bytes only in worker memory; return bounded, secret-free metadata."""
    row: dict[str, Any] = {"file": filename, "status": "unavailable",
                           "line": None, "column": None, "reason": None,
                           "error_code": None, "explanation_fa": None}
    if not _NAME.fullmatch(filename) or len(encoded) > (MAX_FILE_BYTES * 4 // 3 + 16):
        row["reason"] = "unsafe_or_oversized"
        return row
    try:
        content = base64.b64decode(encoded, validate=True)
        if len(content) > MAX_FILE_BYTES:
            row["reason"] = "oversized"
            return row
        text_value = content.decode("utf-8-sig")
        json.loads(normalize_dotnet_json(text_value),
                   parse_constant=_reject_constant,
                   object_pairs_hook=_reject_duplicate_keys)
        row["status"] = "valid_json_syntax"
    except DotnetJsonCommentError as error:
        row.update({
            "status": "invalid_json_syntax", "reason": "unclosed_json_comment",
            "error_code": "json_unclosed_comment", "line": error.line,
            "column": error.column,
            "explanation_fa": "کامنت /* در فایل بسته نشده است.",
        })
    except (UnicodeDecodeError, binascii.Error):
        row.update({"status": "invalid_json_syntax", "reason": "invalid_encoding",
                    "error_code": "json_invalid_encoding",
                    "explanation_fa": "فایل UTF-8 معتبر نیست یا انتقال داده ناقص بوده است."})
    except json.JSONDecodeError as error:
        kind, explanation = _MESSAGES.get(error.msg, (
            "json_syntax_error", "ساختار JSON در این محل نامعتبر است؛ کاراکترهای اطراف خط را در ویرایشگر بررسی کنید."
        ))
        row.update({"status": "invalid_json_syntax", "line": error.lineno,
                    "column": error.colno, "reason": kind,
                    "error_code": kind, "explanation_fa": explanation})
    except ValueError as error:
        # These fixed reason strings have no source content.
        reason = str(error) if str(error) in {
            "nonstandard_json_constant", "duplicate_json_key"
        } else "json_validation_failure"
        row.update({
            "status": "invalid_json_syntax", "reason": reason,
            "error_code": reason,
            "explanation_fa": (
                "کلید تکراری در تنظیمات JSON وجود دارد." if reason == "duplicate_json_key"
                else "مقدار غیرمجاز یا غیر استاندارد در JSON وجود دارد."
            ),
        })
    return row
