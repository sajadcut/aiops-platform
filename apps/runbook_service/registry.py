from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml

from domain.runbook_validation import validate_runbook


class RunbookRegistry:
    """Loads governed runbooks from the repository and validates them before use."""

    def __init__(self, root: str = "runbooks"):
        self.root = Path(root)
        self._cache: Dict[str, Dict[str, Any]] = {}

    def load(self) -> List[Dict[str, Any]]:
        self._cache.clear()
        for path in sorted(self.root.glob("*.yml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            validate_runbook(data)
            name = str(data["name"])
            self._cache[name] = data
        return list(self._cache.values())

    def get(self, name: str) -> Dict[str, Any]:
        if not self._cache:
            self.load()
        try:
            return self._cache[name]
        except KeyError as exc:
            raise KeyError(f"Unknown runbook: {name}") from exc

    def list(self) -> List[Dict[str, Any]]:
        if not self._cache:
            self.load()
        return list(self._cache.values())

    def dry_run(self, name: str) -> Dict[str, Any]:
        runbook = self.get(name)
        return {
            "runbook": name,
            "version": runbook["version"],
            "dry_run": True,
            "steps": runbook.get("steps", []),
            "rollback_steps": runbook.get("rollback_steps", []),
        }
