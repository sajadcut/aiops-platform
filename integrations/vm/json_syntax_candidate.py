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


def deterministic_json_punctuation_fix(source: str) -> str | None:
    """Find a UNIQUE one-byte grammar-only repair near the actual JSON error.

    Only insert/remove a JSON structural punctuation character. Never edit
    string literals, key names, application values, whitespace or remote data.
    Ambiguous/multi-error documents deliberately remain unrepairable.
    """
    try:
        json.loads(source)
        return None
    except json.JSONDecodeError as exc:
        error_pos, error_msg, error_line = exc.pos, exc.msg.lower(), exc.lineno
    if not isinstance(source, str) or len(source) > 262144 or "\x00" in source:
        return None
    # Do not guess from a transport/semantic failure or search the whole file.
    if not any(k in error_msg for k in (
        "property name", "expecting ',' delimiter", "expecting value",
        "extra data", "expecting ':' delimiter",
    )):
        return None
    pos = error_pos
    start = max(0, pos - 96)
    end = min(len(source), pos + 48)
    # Scan lexical string state only once. Quotes and escaped data are never
    # altered, even when punctuation appears within a secret.
    inside = []
    quoted = escaped = False
    for ch in source[:end + 1]:
        inside.append(quoted)
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
    matches: set[str] = set()
    line = error_line
    def local(index: int) -> bool:
        # An error after a dangling comma often points to the NEXT line.
        return abs(source.count("\n", 0, index) + 1 - line) <= 2

    # Removing an *extra* comma/brace/bracket is strictly grammar-only.
    # A deletion must be close to the decoder's measured failing offset.
    for i in range(start, end):
        if not local(i) or inside[i] or source[i] not in ",{}[]":
            continue
        candidate = source[:i] + source[i + 1:]
        try:
            json.loads(candidate)
        except json.JSONDecodeError:
            continue
        matches.add(candidate)
        if len(matches) > 1:
            return None

    # The other common one-byte typo: missing separator before a property or
    # array element. Require a preceding completed token; no punctuation is
    # injected into text, values or an already quoted string.
    if "delimiter" in error_msg or "property name" in error_msg:
        at = pos
        while at < len(source) and source[at] in " \t\r\n":
            at += 1
        before = pos - 1
        while before >= 0 and source[before] in " \t\r\n":
            before -= 1
        if (0 <= at < len(source) and before >= 0 and local(at)
                and not inside[at] and source[before] in '0123456789"}]el'
                and source[at] in '"{[-0123456789tfn'):
            candidate = source[:at] + "," + source[at:]
            try:
                json.loads(candidate)
            except json.JSONDecodeError:
                pass
            else:
                matches.add(candidate)
    return next(iter(matches)) if len(matches) == 1 else None
