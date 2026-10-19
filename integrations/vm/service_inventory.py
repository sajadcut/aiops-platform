"""Bounded, allowlist-scoped parsing of untrusted systemd unit output."""
from __future__ import annotations
import re
from typing import Any

_UNIT = re.compile(r"^[A-Za-z0-9@_.:-]{1,128}\.service$")


def parse_systemd_services(output: str, *, allowed_services: set[str] | None = None,
                           query: str | None = None, state: str | None = None,
                           limit: int = 250) -> dict[str, Any]:
    if state not in (None, "failed"):
        raise ValueError("invalid_service_state_filter")
    if query is not None and (not isinstance(query, str) or len(query) > 80):
        raise ValueError("invalid_service_search_query")
    limit = max(1, min(int(limit), 500))
    allowed = {str(name).removesuffix(".service") for name in (allowed_services or set())}
    restrictive = allowed_services is not None
    selected: list[dict[str, str]] = []
    matched = 0
    lines = output.splitlines()
    for raw in lines[:5000]:
        fields = raw.strip().removeprefix("●").strip().split(None, 4)
        if len(fields) < 4 or not _UNIT.fullmatch(fields[0]):
            continue
        name = fields[0]
        if restrictive and name.removesuffix(".service") not in allowed:
            continue
        load, active, sub = fields[1:4]
        if not all(re.fullmatch(r"[A-Za-z-]{1,32}", x) for x in (load, active, sub)):
            continue
        desc = "".join(ch for ch in (fields[4] if len(fields) > 4 else "")[:200] if ch.isprintable())
        if state == "failed" and active != "failed":
            continue
        if query and query.casefold() not in f"{name} {desc}".casefold():
            continue
        matched += 1
        if len(selected) < limit:
            selected.append({"name": name, "load_state": load, "active_state": active,
                             "sub_state": sub, "description": desc})
    return {"services": selected, "matching_count": matched,
            "truncated": matched > limit or len(lines) > 5000,
            "scope": "allowlisted_services" if restrictive else "all_visible_systemd_services",
            "scope_restricted": restrictive, "filter_state": state, "query": query}
