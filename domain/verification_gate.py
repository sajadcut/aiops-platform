from typing import Any, Dict

ALLOWED = {"success", "partial", "failed", "inconclusive"}

def verification_gate(result: Dict[str, Any]) -> Dict[str, Any]:
    status = str(result.get("status", "inconclusive"))
    confidence = float(result.get("confidence", 0.0))
    passed = status == "success" and confidence >= 0.70
    return {"passed": passed, "status": status if status in ALLOWED else "inconclusive", "confidence": confidence}
