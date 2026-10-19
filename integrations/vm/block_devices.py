"""Bounded read-only Linux block-device and mount-option parsing."""
from __future__ import annotations

import re
import shlex
from typing import Any


_SAFE_DEVICE = re.compile(r"^[A-Za-z0-9_.:+-]{1,100}$")
_VALID_TYPES = {"disk", "part", "lvm", "raid0", "raid1", "raid4", "raid5",
                "raid6", "raid10", "rom", "loop", "crypt", "md"}


def parse_block_devices(output: str, *, limit: int = 256) -> list[dict[str, Any]]:
    devices = []
    for line in output.splitlines()[:1000]:
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            continue
        attrs = dict(token.split("=", 1) for token in tokens if "=" in token)
        name = attrs.get("NAME", "")
        kind = attrs.get("TYPE", "")
        size = attrs.get("SIZE", "")
        ro = attrs.get("RO", "")
        if (not _SAFE_DEVICE.fullmatch(name) or kind not in _VALID_TYPES
                or not size.isdigit() or int(size) > 2**63 - 1
                or ro not in {"0", "1"}):
            continue
        mount = attrs.get("MOUNTPOINT", "")
        devices.append({
            "device": "/dev/" + name,
            "type": kind, "size_bytes": int(size),
            "filesystem_type": attrs.get("FSTYPE", "")[:48],
            "mount": mount[:180] if mount.startswith("/") else "",
            "read_only": ro == "1",
        })
        if len(devices) >= limit:
            break
    return devices


def parse_mount_modes(output: str) -> dict[str, bool]:
    modes = {}
    for line in output.splitlines()[:1000]:
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or not fields[0].startswith("/"):
            continue
        options = fields[1].split(",")
        if "ro" in options or "rw" in options:
            modes[fields[0]] = "ro" in options
    return modes
