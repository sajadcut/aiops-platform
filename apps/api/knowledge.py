from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.rag_service import KnowledgeRAGService
from apps.security.auth import require_permission
from database import AsyncSessionLocal

router = APIRouter()


class KnowledgeCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1)
    source: str = Field(min_length=1, max_length=255)
    version: Optional[str] = Field(default=None, max_length=50)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=1)
    limit: int = Field(default=5, ge=1, le=50)
    min_similarity: float = Field(default=0.5, ge=0.0, le=1.0)


@router.get("/knowledge")
async def list_knowledge(limit: int = 100, _user=Depends(require_permission("read:incident"))):
    limit = max(1, min(limit, 500))
    async with AsyncSessionLocal() as db:
        return {"items": await KnowledgeRAGService(db).get_all_documents(limit=limit)}


@router.post("/knowledge", status_code=201)
async def create_knowledge(
    payload: KnowledgeCreateRequest,
    _user=Depends(require_permission("manage:knowledge")),
):
    async with AsyncSessionLocal() as db:
        doc_id = await KnowledgeRAGService(db).add_document(
            title=payload.title,
            content=payload.content,
            source=payload.source,
            version=payload.version,
            metadata=payload.metadata,
        )
        return {"id": str(doc_id), "status": "created"}


@router.get("/knowledge/{document_id}")
async def get_knowledge(document_id: UUID, _user=Depends(require_permission("read:incident"))):
    async with AsyncSessionLocal() as db:
        docs = await KnowledgeRAGService(db).get_all_documents(limit=500)
        for item in docs:
            if item["id"] == str(document_id):
                return item
    raise HTTPException(status_code=404, detail="Knowledge document not found")


@router.delete("/knowledge/{document_id}")
async def delete_knowledge(
    document_id: UUID,
    _user=Depends(require_permission("manage:knowledge")),
):
    async with AsyncSessionLocal() as db:
        deleted = await KnowledgeRAGService(db).delete_document(document_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Knowledge document not found")
        return {"id": str(document_id), "status": "deleted"}


@router.post("/knowledge/search")
async def search_knowledge(
    payload: KnowledgeSearchRequest,
    _user=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        items = await KnowledgeRAGService(db).search(
            payload.query,
            limit=payload.limit,
            min_similarity=payload.min_similarity,
        )
        return {"items": items}