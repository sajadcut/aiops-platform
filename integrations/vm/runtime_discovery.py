"""Read-only technology discovery from systemd; no arbitrary shell or secret disclosure.

The service unit is authoritative for the executable identity, but its content is
untrusted as a command source. Never execute its argv, or show environment values.
The systemd metadata parser discovers bounded .NET publish paths. The AIOps
worker validates JSON syntax; no Python interpreter runs on target machines.
"""
from __future__ import annotations

import posixpath
import re
import shlex
from typing import Any

_PATH = re.compile(r"^/(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+$")
_DOTNET = re.compile(r"^(?:dotnet|dotnet[0-9]*)(?:\.exe)?$", re.I)


def safe_absolute_path(value: Any) -> str | None:
    path = str(value or "").strip()
    if len(path) > 300 or not _PATH.fullmatch(path) or posixpath.normpath(path) != path:
        return None
    if any(part in {".", ".."} for part in path.split("/")):
        return None
    return path


def parse_systemd_runtime(output: str, *, service: str) -> dict[str, Any]:
    """Extract only allowlisted non-secret fields; no ExecStart/env value returned."""
    props: dict[str, str] = {}
    for line in str(output or "")[:8000].splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {
            "ExecStart", "WorkingDirectory", "FragmentPath", "DropInPaths",
            "Type", "TimeoutStartUSec", "Restart",
        }:
            props[key] = value.strip()[:3000]

    command = props.get("ExecStart", "")
    match = re.search(r"argv\[\]=(.*?)(?:\s;\s|})", command, re.S)
    try:
        argv = shlex.split(match.group(1).strip() if match else command)
    except ValueError:
        argv = []
    binary = posixpath.basename(argv[0]) if argv else ""
    dll = next((
        safe_absolute_path(arg) for arg in argv[1:4]
        if str(arg).lower().endswith(".dll") and safe_absolute_path(arg)
    ), None)
    runtime = "dotnet" if _DOTNET.fullmatch(binary) and dll else "unknown"
    publish = posixpath.dirname(dll) if runtime == "dotnet" else None
    # Do not inspect system locations or single-component directories as
    # publish roots. The remote script verifies symlinks again.
    if publish and (
        len(publish.split("/")) < 3 or
        publish.startswith(("/proc/", "/sys/", "/dev/", "/etc/")) or
        publish in {"/", "/tmp", "/var", "/home", "/opt", "/data", "/srv"}
    ):
        runtime, publish, dll = "unknown", None, None
    return {
        "service": service,
        "runtime": runtime,
        "runtime_source": "systemd_execstart",
        "entrypoint": dll,
        "publish_directory": publish,
        "unit_file": safe_absolute_path(props.get("FragmentPath")),
        "working_directory": safe_absolute_path(props.get("WorkingDirectory")),
        "service_type": props.get("Type", "")[:32],
        "restart_policy": props.get("Restart", "")[:50],
        "timeout_start_usec": props.get("TimeoutStartUSec", "")[:40],
        "environment_values_read": False,
        "config_contents_exposed": False,
    }


