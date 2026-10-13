"""Read-only technology discovery from systemd; no arbitrary shell or secret disclosure.

The service unit is authoritative for the executable identity, but its content is
untrusted as a command source. Never execute its argv, or show environment values.
The only remote parser accepts derived, bounded .NET publish directories and
checks JSON *syntax*, never application health or semantic configuration.
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


# Executed ONLY as a fixed, version-controlled diagnostic against a directory
# discovered by parsing systemctl (never a model-, alert-, or request-supplied
# filename). Script emits metadata and parse errors, not contents/values.
_DOTNET_JSON_CHECK = r'''
import json, os, re, stat, sys
root = sys.argv[1]
result = {"status": "unavailable", "syntax_valid": None, "files": [],
          "values_exposed": False, "validator": "python3-json-syntax-only"}
try:
    if os.path.realpath(root) != root or not os.path.isdir(root):
        raise ValueError("unsafe_publish_directory")
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = sorted(os.listdir(directory_fd))
        if len(names) > 500:
            raise ValueError("too_many_directory_entries")
        candidates = [
            n for n in names
            if re.fullmatch(r"appsettings(?:\.[A-Za-z0-9_-]{1,40})?\.json", n, re.I)
            or re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}\.runtimeconfig\.json", n, re.I)
        ]
        files = candidates[:12]
        if not files:
            result["status"] = "not_found"
        else:
            failures = False
            incomplete = len(candidates) > len(files)
        for name in files:
            p = os.path.join(root, name)
            item = {"file": name, "status": "unavailable"}
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, "rb") as stream:
                    meta = os.fstat(stream.fileno())
                    content = stream.read(1048577) if stat.S_ISREG(meta.st_mode) and meta.st_size <= 1048576 else b""
                if not stat.S_ISREG(meta.st_mode) or meta.st_size > 1048576:
                    item["reason"] = "non_regular_or_oversized"
                    incomplete = True
                else:
                    if len(content) > 1048576:
                        item["reason"] = "oversized"
                        incomplete = True
                    else:
                        def reject_constant(_):
                            raise ValueError("nonstandard_json_constant")
                        def reject_duplicates(pairs):
                            seen = set()
                            for key, _ in pairs:
                                if key in seen:
                                    raise ValueError("duplicate_json_key")
                                seen.add(key)
                            return dict(pairs)
                        json.loads(content.decode("utf-8-sig"),
                                   parse_constant=reject_constant,
                                   object_pairs_hook=reject_duplicates)
                        item["status"] = "valid_json_syntax"
            except json.JSONDecodeError as exc:
                item.update({"status": "invalid_json_syntax",
                             "line": exc.lineno, "column": exc.colno})
                failures = True
            except (ValueError, UnicodeError) as exc:
                item.update({"status": "invalid_json_syntax",
                             "reason": type(exc).__name__})
                failures = True
            except OSError:
                item["reason"] = "file_not_readable"
                incomplete = True
            result["files"].append(item)
            result["status"] = "invalid" if failures else ("partial" if incomplete else "syntax_valid")
            result["syntax_valid"] = False if failures else (None if incomplete else True)
    finally:
        os.close(directory_fd)
except (ValueError, OSError):
    result["status"] = "unavailable"
print(json.dumps(result, separators=(",", ":")))
'''


def dotnet_json_syntax_command(publish_directory: str) -> str:
    directory = safe_absolute_path(publish_directory)
    if not directory or directory in {"/tmp", "/opt", "/srv", "/data", "/home", "/var"}:
        raise ValueError("invalid_publish_directory")
    return "python3 -I -c " + shlex.quote(_DOTNET_JSON_CHECK) + " " + shlex.quote(directory)
