"""Value-free grammar projection for LLM review. Never returns config values."""
from __future__ import annotations
import re

KNOWN = frozenset((
    "global", "defaults", "frontend", "backend", "listen", "bind",
    "server", "mode", "timeout", "option", "acl", "use_backend",
    "http", "tcp", "events", "stream", "upstream", "location", "map",
    "include", "if", "else", "end", "true", "false", "null",
))
WORDS = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+|[^\w\s]", re.ASCII)


def project_line(line: str, extension: str) -> str:
    if not line.strip() or line.lstrip().startswith(("#", "//", ";", "<!--")):
        return ""
    if extension == "json":
        # Mask quoted strings before retaining JSON grammar punctuation.
        text = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
        return "".join(c if c in '{}[],: \t' else 'x' for c in text)[:180]
    # Treat quoted values and inline comments as entirely opaque.
    # The model only needs the surrounding syntax; values are never tokens.
    scrubbed = []
    quote = None
    escaped = False
    for ch in line[:1000]:
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            scrubbed.append(" x ")
            quote = ch
            continue
        if ch == "#":
            break
        scrubbed.append(ch)
    tokens = []
    for word in WORDS.findall("".join(scrubbed)):
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", word):
            tokens.append(word if word.lower() in KNOWN else "x")
        elif word.isdigit():
            tokens.append("0")
        elif word in "{}[](),:=;<>/-+*":
            tokens.append(word)
        else:
            tokens.append("_")
    return " ".join(tokens)[:180]


def syntax_projection(source: str, *, extension: str, error_line: int | None = None) -> dict:
    lines = source.splitlines()
    start = max(0, error_line - 35) if isinstance(error_line, int) and error_line > 0 else 0
    end = min(len(lines), start + 120)
    output = [
        {"line": i + 1, "indent": min(len(lines[i]) - len(lines[i].lstrip()), 32),
         "syntax": project_line(lines[i], extension.lower().lstrip("."))}
        for i in range(start, end)
    ]
    return {"lines": output, "total_lines": len(lines), "truncated": start > 0 or end < len(lines),
            "representation": "value_free_syntax_tokens", "vendor_validated": False}
