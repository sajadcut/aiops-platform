"""Produce an auditable strict-JSON candidate from a broken .NET JSONC file.

System.Text.Json configuration accepts comments and trailing commas, while
jq/Python json do not. This helper deliberately normalizes only those .NET-
accepted syntax features before a bounded deterministic grammar correction.
The resulting strict JSON can be validated independently with staged jq, and
reconstructed from identical live source bytes after the operator approves.

Only the VM MCP worker sees source and candidate. The orchestration layer
receives hashes and a redacted structural change summary, never values.
"""
from __future__ import annotations

import json
import re

from integrations.vm.dotnet_local_validator import (
    normalize_dotnet_json,
    _reject_constant,
    _reject_duplicate_keys,
    DotnetJsonCommentError,
)
from integrations.vm.json_syntax_candidate import (
    bounded_json_repair_with_edits,
    deterministic_json_syntax_fix,
    deterministic_json_punctuation_fix,
    deterministic_json_duplicate_brace_fix,
)


def _parse_strict(source: str) -> None:
    json.loads(source, parse_constant=_reject_constant,
               object_pairs_hook=_reject_duplicate_keys)


def dotnet_json_repair(source: str) -> tuple[str, list[dict]] | None:
    """Find a *unique*, parser-valid JSON candidate; do not guess values.

    A valid .NET JSONC document is never rewritten just for normalizing it.
    A broken one may require removing comments/trailing commas as part of
    producing a strict-JSON candidate for independent `jq empty` validation.
    Neither this helper nor its callers may apply a candidate to the VM.
    """
    if (not isinstance(source, str) or '\x00' in source or
            not 1 <= len(source.encode('utf-8')) <= 65536):
        return None
    try:
        normalized = normalize_dotnet_json(source)
    except DotnetJsonCommentError:
        return None
    try:
        _parse_strict(normalized)
        return None  # .NET sees a healthy file; do not alter it.
    except json.JSONDecodeError as error:
        line = error.lineno
    except ValueError:
        # Duplicate keys/NaN are semantic hazards, not safe punctuation typos.
        return None

    candidate = None
    details = []
    staged = bounded_json_repair_with_edits(normalized, max_edits=6)
    if staged:
        candidate, details = staged
    if candidate is None:
        # Already versioned deterministic transforms give a unique full parse.
        for repair in (
            deterministic_json_syntax_fix,
            deterministic_json_punctuation_fix,
            deterministic_json_duplicate_brace_fix,
        ):
            attempted = repair(normalized)
            if attempted is not None:
                candidate = attempted
                details = [{"line": line, "before": "json_invalid_punctuation",
                            "after": "json_syntax_repaired"}]
                break
    if candidate is None:
        return None
    try:
        _parse_strict(candidate)
    except (json.JSONDecodeError, ValueError):
        return None
    # The bounded repair changes structural tokens only. Never modify even
    # a single non-grammar byte in the normalized document (keys or values).
    remove_grammar = lambda s: re.sub(r'[{}\[\],:"]', '', s)
    if remove_grammar(normalized) != remove_grammar(candidate):
        return None
    redacted = []
    if normalized != source:
        redacted.append({"line": line, "before": "dotnet_jsonc_comments_or_trailing_commas",
                         "after": "strict_json_validator_compatible"})
    redacted.extend(details[:6])
    return candidate, redacted


def dotnet_json_candidate(source: str) -> str | None:
    result = dotnet_json_repair(source)
    return result[0] if result else None