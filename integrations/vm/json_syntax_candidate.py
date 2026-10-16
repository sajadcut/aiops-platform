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


def deterministic_json_duplicate_brace_fix(source: str) -> str | None:
    """Delete exactly one superfluous opening and closing brace.

    Models sometimes produce no parseable plan for "{{ ... }}" typos. Only
    attempt this unambiguous two-byte repair after a measured JSON failure.
    All non-brace bytes (including secrets, names and whitespace) stay intact;
    no remote file is written. Multiple valid candidates fail closed.
    """
    if not isinstance(source, str) or not 1 <= len(source) <= 65536 or "\x00" in source:
        return None
    try:
        json.loads(source)
        return None
    except json.JSONDecodeError as error:
        pos, error_line = error.pos, error.lineno
    # Preserve strings verbatim. Never delete a brace in a quoted value.
    outside = []
    quoted = escaped = False
    for ch in source:
        outside.append(not quoted)
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
    # The duplicate opener must be on the measured error line or the
    # immediately preceding line; matched closer can be further down.
    openers = [
        i for i in range(max(0, pos - 180), min(len(source) - 1, pos + 100))
        if source[i:i + 2] == "{{" and outside[i] and outside[i + 1]
        and abs(source.count("\n", 0, i) + 1 - error_line) <= 2
    ]
    if not openers:
        return None
    matches = set()
    for left in openers[:8]:
        # A double closer is the symmetrical, grammar-only counterpart.
        # Limit scope to the next 30 lines to avoid editing other objects.
        end = min(len(source) - 1, left + 4096)
        for right in range(left + 2, end):
            if (source[right:right + 2] != "}}" or not outside[right]
                    or not outside[right + 1]
                    or source.count("\n", left, right) > 30):
                continue
            candidate = (source[:left] + source[left + 1:right]
                         + source[right + 1:])
            try:
                json.loads(candidate)
            except json.JSONDecodeError:
                continue
            matches.add(candidate)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


def bounded_json_repair_with_edits(source: str, max_edits: int = 3):
    """Recover successive measured grammar faults without touching values.

    Every intermediate document is parsed again; only structural punctuation
    outside JSON strings or quoting one bare key can change. Edits are capped
    at three characters, alternatives must converge to ONE final document,
    and no original/candidate text or key names are returned in metadata.
    This is a preview/validation candidate, NEVER permission to execute.
    """
    if (not isinstance(source, str) or "\x00" in source
            or not 1 <= len(source.encode("utf-8")) <= 262144
            or type(max_edits) is not int or not 1 <= max_edits <= 3):
        return None
    try:
        json.loads(source)
        return None
    except json.JSONDecodeError:
        pass

    frontier = {0: {source: ()}}
    visited = {source: 0}
    successes = {}
    for spent in range(max_edits):
        for text, history in frontier.get(spent, {}).items():
            try:
                json.loads(text)
            except json.JSONDecodeError as caught:
                error = caught
            else:
                continue
            pos = error.pos
            detail = error.msg.lower()
            if not any(token in detail for token in (
                "property name", "expecting value", "expecting ',' delimiter",
                "expecting ':' delimiter", "extra data",
            )):
                continue

            inside = []
            quoted = escaped = False
            for char in text[:min(len(text), pos + 5)]:
                inside.append(quoted)
                if quoted:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == '"':
                        quoted = False
                elif char == '"':
                    quoted = True

            proposals = {}

            def add(candidate, label, at, cost):
                if (candidate == text or len(candidate) > 262144
                        or spent + cost > max_edits):
                    return
                # No file bytes or arbitrary key names in this edit history.
                change = (label, text[:at].count("\n") + 1, cost)
                proposals.setdefault(candidate, (history + (change,), cost))

            if "property name" in detail and pos < len(text) and not inside[pos]:
                match = re.match(
                    r"([A-Za-z_][A-Za-z0-9_.-]*)(?=\s*:)", text[pos:],
                )
                if match:
                    end = pos + len(match.group(1))
                    add(text[:pos] + '"' + text[pos:end] + '"' + text[end:],
                        "quote_unquoted_key", pos, 2)

            positions = set(range(max(0, pos - 3), min(len(text), pos + 4)))
            before = pos - 1
            while before >= 0 and text[before] in " \r\n\t":
                before -= 1
            if before >= 0:
                positions.add(before)
            after = pos
            while after < len(text) and text[after] in " \r\n\t":
                after += 1
            if after < len(text):
                positions.add(after)
            names = {"{": "remove_opening_brace", "}": "remove_closing_brace",
                     "[": "remove_opening_bracket", "]": "remove_closing_bracket",
                     ",": "remove_comma", ":": "remove_colon"}
            for at in sorted(positions):
                if at >= len(inside) or inside[at] or text[at] not in names:
                    continue
                add(text[:at] + text[at + 1:], names[text[at]], at, 1)

            if ("expecting ',' delimiter" in detail
                    or ("property name" in detail
                        and pos < len(text) and text[pos] == '"')):
                if pos <= len(text) and (pos == len(text) or not inside[pos]):
                    add(text[:pos] + "," + text[pos:], "insert_comma", pos, 1)
            if "expecting ':' delimiter" in detail:
                if pos <= len(text) and (pos == len(text) or not inside[pos]):
                    add(text[:pos] + ":" + text[pos:], "insert_colon", pos, 1)
            if pos == len(text) and "expecting" in detail:
                for glyph, name in (("}", "insert_closing_brace"),
                                    ("]", "insert_closing_bracket")):
                    add(text + glyph, name, pos, 1)

            for proposed, (changes, cost) in proposals.items():
                new_cost = spent + cost
                if proposed in visited and visited[proposed] <= new_cost:
                    continue
                visited[proposed] = new_cost
                try:
                    json.loads(proposed)
                except json.JSONDecodeError as next_error:
                    # Do not speculate backwards or explore arbitrary source.
                    bucket = frontier.setdefault(new_cost, {})
                    if next_error.pos >= error.pos and len(bucket) < 128:
                        bucket[proposed] = changes
                else:
                    successes.setdefault(new_cost, {})[proposed] = changes

        if successes.get(spent + 1):
            # Different *complete* outputs at the same minimal edit distance
            # are ambiguous and may alter application semantics. Fail closed.
            solutions = successes[spent + 1]
            if len(solutions) != 1:
                return None
            corrected, steps = next(iter(solutions.items()))
            return corrected, [
                {"line": step[1], "before": step[0],
                 "after": "json_syntax_repaired"}
                for step in steps
            ]
    return None


def bounded_json_syntax_fix(source: str) -> str | None:
    """Pure deterministic replay of a bounded worker-generated JSON patch."""
    result = bounded_json_repair_with_edits(source)
    return result[0] if result else None
