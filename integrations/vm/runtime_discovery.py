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



_CONFIG_EXT = (".conf", ".cfg", ".cnf", ".xml", ".properties", ".yaml", ".yml",
               ".json", ".ini", ".toml", ".hcl", ".config")
_BLOCKED_ROOTS = ("/proc/", "/sys/", "/dev/", "/run/secrets/", "/etc/shadow", "/etc/ssh/", "/etc/ssl/private/")
_JAVA = re.compile(r"^(?:java|java[0-9]+|jsvc|catalina\.sh|startup\.sh)$", re.I)

def _candidate_path(value: Any) -> str | None:
    path = safe_absolute_path(value)
    return path if path and len(path) < 240 and not path.startswith(_BLOCKED_ROOTS) and path.lower().endswith(_CONFIG_EXT) else None

def systemd_config_candidates(argv: list[str], *, runtime: str) -> list[dict]:
    """Unit-sourced path hypotheses; neither presence nor validity implied."""
    result: dict[str, dict] = {}
    def add(value, source, confidence="unit_argument"):
        path = _candidate_path(value)
        if path and path not in result and len(result) < 10:
            result[path] = {"path": path, "source": source, "confidence": confidence,
                            "verified_exists": False, "content_validated": False}
    for i, arg in enumerate(argv[:48]):
        for flag in ("-Dspring.config.location=", "-Dspring.config.additional-location=",
                     "-Dlogging.config=", "--config=", "--config-file=", "--spring.config.location=",
                     "--spring.config.additional-location="):
            if arg.startswith(flag):
                value = arg[len(flag):].removeprefix("file:")
                if "," not in value and not value.startswith("classpath:"):
                    add(value, "systemd_config_argument")
        if arg in {"-f", "-c", "--config", "--config-file", "--spring.config.location"} and i + 1 < len(argv):
            add(argv[i + 1].removeprefix("file:"), "systemd_config_flag")
    if runtime == "tomcat":
        base = next((arg.split("=", 1)[1] for arg in argv[:48]
                     if arg.startswith("-Dcatalina.base=")), "")
        safe = safe_absolute_path(base)
        if safe and len(safe) <= 205 and len(safe.strip("/").split("/")) >= 2 and not safe.startswith(_BLOCKED_ROOTS):
            for suffix in ("/conf/server.xml", "/conf/context.xml", "/conf/web.xml"):
                add(safe + suffix, "systemd_catalina_base", "path_hypothesis")
    return list(result.values())


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
    runtime = "dotnet" if _DOTNET.fullmatch(binary) and dll else (
        "tomcat" if _JAVA.fullmatch(binary) and (
            any(arg.startswith("-Dcatalina.base=") for arg in argv)
            or any("org.apache.catalina.startup.Bootstrap" in arg for arg in argv)
            or binary.lower() in {"catalina.sh", "startup.sh"}
        ) else "java" if _JAVA.fullmatch(binary) else "unknown"
    )
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
        "config_candidates": systemd_config_candidates(argv, runtime=runtime),
        "config_discovery_status": ("unit_candidates_unverified"
            if systemd_config_candidates(argv, runtime=runtime) else "no_explicit_config_path"),
        "service_type": props.get("Type", "")[:32],
        "restart_policy": props.get("Restart", "")[:50],
        "timeout_start_usec": props.get("TimeoutStartUSec", "")[:40],
        "environment_values_read": False,
        "config_contents_exposed": False,
    }


