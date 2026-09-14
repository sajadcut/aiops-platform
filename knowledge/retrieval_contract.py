from typing import Any, Dict

BASE_REQUIRED = ("source_id", "provider", "relevance", "retrieved_at")
COGNIA_REQUIRED = (
    "knowledge_base_id",
    "knowledge_id",
    "revision_id",
    "revision_number",
    "chunk_id",
    "version",
    "content",
)


def validate_retrieval(item: Dict[str, Any]) -> bool:
    if not all(key in item for key in BASE_REQUIRED):
        return False
    if str(item.get("provider") or "").strip().lower() != "cognia":
        return False
    try:
        relevance = float(item.get("relevance"))
    except (TypeError, ValueError):
        return False
    if not 0.0 <= relevance <= 1.0:
        return False
    return all(key in item and item.get(key) is not None for key in COGNIA_REQUIRED)
