from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml

from domain.runbook_validation import validate_runbook


class RunbookRegistry:
    """Loads governed runbooks and rejects malformed definitions fail-closed."""

    def __init__(self, root: str = "runbooks"):
        self.root = Path(root)
        self._cache: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _identity(data: Dict[str, Any]) -> str:
        return str(data.get("id") or data.get("name") or "").strip()

    def load(self) -> List[Dict[str, Any]]:
        self._cache.clear()
        for path in sorted(self.root.glob("*.yml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            result = validate_runbook(data)
            if not result["valid"]:
                raise ValueError(
                    f"invalid_runbook:{path.name}:missing={result['missing']}:errors={result['errors']}"
                )
            runbook_id = self._identity(data)
            if runbook_id in self._cache:
                raise ValueError(f"duplicate_runbook_id:{runbook_id}")
            normalized = dict(data)
            normalized.setdefault("id", runbook_id)
            normalized.setdefault("name", runbook_id)
            self._cache[runbook_id] = normalized
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

    def validate(self, name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Revalidate static governance before execution.

        Runtime preconditions must be supplied/checked by the incident workflow
        against Live Evidence; arbitrary API parameters cannot assert that a
        production precondition is true. This method therefore validates the
        immutable registry contract and returns preconditions for the caller to
        bind to authoritative Evidence.
        """
        runbook = self.get(name)
        result = validate_runbook(runbook)
        if not result["valid"]:
            raise ValueError(f"invalid_runbook:{name}")
        return {
            **result,
            "parameters": dict(parameters or {}),
            "preconditions": list(runbook.get("preconditions") or []),
            "verification": dict(runbook.get("verification") or {}),
            "risk": runbook.get("risk"),
            "version": runbook.get("version"),
        }

    def dry_run(self, name: str) -> Dict[str, Any]:
        runbook = self.get(name)
        self.validate(name, {})
        return {
            "runbook": name,
            "version": runbook["version"],
            "risk": runbook.get("risk"),
            "dry_run": True,
            "preconditions": runbook.get("preconditions", []),
            "steps": runbook.get("steps", []),
            "rollback": runbook.get("rollback", []),
            "verification": runbook.get("verification", {}),
        }
