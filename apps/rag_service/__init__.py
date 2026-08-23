from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from domain.models import KnowledgeDocument
from knowledge import EmbeddingService
from domain.contracts.logging import logger

class KnowledgeRAGService:
    """
    سرویس مدیریت دانش و جستجوی معنایی (RAG)
    با پشتیبانی از pgvector برای جستجوی شباهت
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def add_document(
        self,
        title: str,
        content: str,
        source: str,
        version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> UUID:
        """
        افزودن یک سند دانش جدید به دیتابیس
        """
        # تولید Embedding برای محتوا
        embedding = await EmbeddingService.generate_embedding(content)
        
        doc = KnowledgeDocument(
            id=uuid4(),
            title=title,
            content=content,
            source=source,
            version=version,
            extra_metadata=metadata or {},
            embedding=embedding
        )
        
        self.db.add(doc)
        await self.db.commit()
        await self.db.refresh(doc)
        
        logger.info(f"Added knowledge document: {title} (ID: {doc.id})")
        return doc.id
    
    async def search(
        self,
        query: str,
        limit: int = 5,
        min_similarity: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        جستجوی معنایی در اسناد دانش با استفاده از pgvector
        """
        # تولید Embedding برای query
        query_embedding = await EmbeddingService.generate_embedding(query)
        
        # جستجو با استفاده از cosine distance
        stmt = (
            select(
                KnowledgeDocument,
                KnowledgeDocument.embedding.cosine_distance(query_embedding).label("distance")
            )
            .where(KnowledgeDocument.embedding.is_not(None))
            .order_by("distance")
            .limit(limit)
        )
        
        result = await self.db.execute(stmt)
        rows = result.all()
        
        documents = []
        for row in rows:
            doc = row[0]
            distance = row[1]
            similarity = 1 - distance  # تبدیل فاصله به شباهت
            
            if similarity >= min_similarity:
                documents.append({
                    "id": str(doc.id),
                    "title": doc.title,
                    "content": doc.content[:500] + "..." if len(doc.content) > 500 else doc.content,
                    "source": doc.source,
                    "version": doc.version,
                    "extra_metadata": doc.extra_metadata,
                    "similarity": float(similarity)
                })
        
        logger.info(f"RAG search returned {len(documents)} documents")
        return documents
    
    async def get_all_documents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        دریافت لیست همه اسناد دانش (بدون جستجو)
        """
        stmt = select(KnowledgeDocument).limit(limit)
        result = await self.db.execute(stmt)
        docs = result.scalars().all()
        
        return [
            {
                "id": str(doc.id),
                "title": doc.title,
                "content": doc.content[:200] + "..." if len(doc.content) > 200 else doc.content,
                "source": doc.source,
                "version": doc.version,
                "extra_metadata": doc.extra_metadata,
                "created_at": doc.created_at.isoformat()
            }
            for doc in docs
        ]
    
    async def delete_document(self, doc_id: UUID) -> bool:
        """
        حذف یک سند دانش
        """
        stmt = select(KnowledgeDocument).where(KnowledgeDocument.id == doc_id)
        result = await self.db.execute(stmt)
        doc = result.scalar_one_or_none()
        
        if not doc:
            return False
        
        await self.db.delete(doc)
        await self.db.commit()
        
        logger.info(f"Deleted knowledge document: {doc_id}")
        return True