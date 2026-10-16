"""One-token, value-preserving JSON syntax correction on the trusted VM worker.

Only return a complete parseable candidate for an unquoted property name or a
single dangling comma. Never return a diff, a file excerpt or a guessed value.
"""
from __future__ import annotations

import json
import re


def deterministic_json_syntax_fix(source: str) -> str | None:
    """Repair one measured JSON grammar error; fail closed otherwise."""
    try:
        json.loads(source)
        return None
    except json.JSONDecodeError as error:
        pos = error.pos
        detail = error.msg.lower()
        candidate = None
        if "property name" in detail:
            bare_key = re.match(r"([A-Za-z_][A-Za-z0-9_.-]*)(?=\s*:)", source[pos:])
            if bare_key:
                end = pos + len(bare_key.group(1))
                candidate = source[:pos] + '"' + source[pos:end] + '"' + source[end:]
        # A trailing comma is reported by the JSON decoder at the closing
        # brace/bracket. Only delete the immediately preceding comma.
        if candidate is None and (
            "property name" in detail or "expecting value" in detail
        ) and pos < len(source) and source[pos] in "}]":
            comma = pos - 1
            while comma >= 0 and source[comma] in " \t\r\n":
                comma -= 1
            if comma >= 0 and source[comma] == ",":
                candidate = source[:comma] + source[comma + 1:]
        if candidate is None:
            return None
        try:
            json.loads(candidate)
        except json.JSONDecodeError:
            return None
        return candidate
