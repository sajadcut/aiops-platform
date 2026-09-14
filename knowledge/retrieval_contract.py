from typing import Any, Dict

BASE_REQUIRED = ("source_id", "provider", "relevance", "retrieved_at")
LOCAL_REQUIRED = ("title", "version")
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
    try:
        relevance = float(item.get("relevance"))
    except (TypeError, ValueError):
        return False
    if not 0.0 <= relevance <= 1.0:
        return False

    provider = str(item.get("provider") or "").strip().lower()
    if provider == "cognia":
        return all(key in item and item.get(key) is not None for key in COGNIA_REQUIRED)
    if provider == "local_pgvector":
        return all(key in item for key in LOCAL_REQUIRED)
    return False
