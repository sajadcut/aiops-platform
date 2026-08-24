from typing import Dict, Any

REQUIRED = ("source_id", "title", "version", "relevance", "retrieved_at")

def validate_retrieval(item: Dict[str, Any]) -> bool:
    return all(key in item for key in REQUIRED) and 0.0 <= float(item.get("relevance", 0.0)) <= 1.0
