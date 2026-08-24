from domain.verification_gate import verification_gate

def test_verification_success_requires_confidence():
    assert verification_gate({"status": "success", "confidence": 0.9})["passed"]

def test_partial_verification_does_not_pass():
    assert not verification_gate({"status": "partial", "confidence": 0.9})["passed"]
