from domain.runbook_validation import validate_runbook

def test_runbook_requires_governance_fields():
    result = validate_runbook({"owner": "sre", "version": "1", "steps": [], "rollback": []})
    assert not result["valid"]
    assert "preconditions" in result["missing"]

def test_runbook_valid_shape():
    result = validate_runbook({"owner": "sre", "version": "1", "preconditions": [], "steps": [], "timeout": 30, "rollback": []})
    assert result["valid"]
