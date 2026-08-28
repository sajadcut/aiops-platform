from __future__ import annotations

from fastapi.routing import APIRoute

from apps.api.main import app


_PUBLIC_API_PATHS = {
    "/api/v1/health",
    "/api/v1/health/live",
    "/api/v1/health/ready",
}


def _has_permission_dependency(route: APIRoute) -> bool:
    stack = list(route.dependant.dependencies)
    seen = set()
    while stack:
        dependency = stack.pop()
        if id(dependency) in seen:
            continue
        seen.add(id(dependency))
        call = dependency.call
        closure = getattr(call, "__closure__", None) or ()
        freevars = getattr(getattr(call, "__code__", None), "co_freevars", ())
        captured = {name: cell.cell_contents for name, cell in zip(freevars, closure)}
        if "required_permission" in captured:
            return True
        stack.extend(dependency.dependencies)
    return False


def test_every_non_public_api_route_has_explicit_permission_dependency():
    missing = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if not path.startswith("/api/v1/") or path in _PUBLIC_API_PATHS:
            continue
        if not _has_permission_dependency(route):
            missing.append(f"{','.join(sorted(route.methods or []))} {path}")
    assert not missing, "Unprotected API routes: " + "; ".join(sorted(missing))
