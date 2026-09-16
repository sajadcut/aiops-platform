#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
from pathlib import Path
from typing import Iterable, TextIO

from domain.contracts.context import incident_rid


def _rid(value: str) -> str:
    raw = str(value or "").strip()
    return raw if raw.startswith("rid_") else incident_rid(raw)


def _open(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _files(log_dir: Path) -> Iterable[Path]:
    # Covers active files plus logrotate date extensions, gzip archives and
    # Python RotatingFileHandler suffixes such as .1/.2.
    return sorted(
        (
            path
            for path in log_dir.glob("aiops*.log*")
            if path.is_file()
        ),
        key=lambda path: (path.stat().st_mtime, path.name),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print all AIOps log lines belonging to one Incident RID."
    )
    parser.add_argument(
        "incident",
        help="Incident UUID or stable rid_<...> value",
    )
    parser.add_argument(
        "--log-dir",
        default="/var/log/aiops",
        help="Directory containing aiops.log / aiops.json.log and rotations",
    )
    args = parser.parse_args()

    rid = _rid(args.incident)
    if not rid:
        parser.error("incident must be a non-empty Incident UUID or RID")

    log_dir = Path(args.log_dir).expanduser()
    matched = 0
    for path in _files(log_dir):
        with _open(path) as handle:
            for line_number, line in enumerate(handle, start=1):
                if rid not in line:
                    continue
                matched += 1
                print(f"{path.name}:{line_number}:{line.rstrip()}")

    if matched == 0:
        print(f"no log lines found for {rid} in {log_dir}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
