from __future__ import annotations

from pathlib import Path

import pytest

from apps.runbook_service.registry import RunbookRegistry
from domain.runbook_validation import validate_runbook


def test_repository_runbooks_load_with_governance_and_verification():
    registry = RunbookRegistry("runbooks")
    items = registry.load()
    assert {item["id"] for item in items} == {
        "app-error-rollback",
        "infrastructure-observation",
        "kubernetes-health",
    }
    for item in items:
        assert item["name"] == item["id"]
        result = registry.validate(item["id"], {})
        assert result["valid"] is True
        assert result["strict"] is True
        assert result["verification"]["checks"]


def test_registry_dry_run_exposes_preconditions_rollback_and_verification():
    result = RunbookRegistry("runbooks").dry_run("app-error-rollback")
    assert result["dry_run"] is True
    assert result["preconditions"]
    assert result["rollback"]
    assert result["verification"]["checks"]
    assert "rollback_steps" not in result


def test_strict_validator_rejects_missing_verification():
    result = validate_runbook({
        "id": "bad",
        "owner": "sre",
        "version": "1",
        "timeout": 30,
        "preconditions": [],
        "steps": [{"action": "inspect"}],
        "rollback": [],
        "risk": "low",
    }, strict=True)
    assert result["valid"] is False
    assert "verification" in result["missing"]


def test_legacy_validator_contract_remains_backward_compatible():
    result = validate_runbook({
        "owner": "sre",
        "version": "1",
        "preconditions": [],
        "steps": [],
        "timeout": 30,
        "rollback": [],
    })
    assert result["valid"] is True
    assert result["strict"] is False


def test_registry_rejects_invalid_runbook_file(tmp_path: Path):
    (tmp_path / "bad.yml").write_text(
        "id: bad\nowner: sre\nversion: '1'\ntimeout: 0\npreconditions: []\nsteps: []\nrollback: []\nrisk: extreme\nverification: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid_runbook"):
        RunbookRegistry(str(tmp_path)).load()
