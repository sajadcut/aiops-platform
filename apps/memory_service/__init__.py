from typing import List, Optional, Dict, Any, cast
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc
from pgvector.sqlalchemy import Vector
from domain.models import MemoryEntry
from knowledge import EmbeddingService  # ✅ اصلاح ایمپورت
from domain.contracts.logging import logger

class OperationalMemoryService:
    """سرویس مدیریت حافظه عملیاتی"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def add_entry(
        self,
        pattern: str,
        symptoms: Dict[str, Any],
        root_cause: Optional[str],
        action: Optional[str],
        verification_result: str,
        outcome: Optional[str],
        environment: Optional[str] = None,
        service_scope: Optional[str] = None,
        incident_id: Optional[UUID] = None
    ) -> UUID:
        """ذخیره‌سازی یک تجربه‌ی جدید"""
        embedding = await EmbeddingService.generate_embedding(pattern)
        
        entry = MemoryEntry(
            id=uuid4(),
            incident_id=incident_id,
            pattern=pattern,
            symptoms=symptoms,
            root_cause=root_cause,
            action=action,
            verification_result=verification_result,
            outcome=outcome,
            environment=environment,
            service_scope=service_scope,
            embedding=embedding,
            reuse_count=0
        )
        self.db.add(entry)
        await self.db.commit()
        await self.db.refresh(entry)
        
        logger.info(f"Added memory entry: {pattern[:50]}... (ID: {entry.id})")
        # ✅ اصلاح نوع بازگشتی: entry.id از نوع UUID است
        return cast(UUID, entry.id)
    
    async def search_similar(
        self,
        query: str,
        service_scope: Optional[str] = None,
        limit: int = 5,
        min_similarity: float = 0.0
    ) -> List[Dict[str, Any]]:
        """جستجوی تجربه‌های مشابه در حافظه"""
        query_embedding = await EmbeddingService.generate_embedding(query)
        
        conditions = []
        # ✅ اصلاح شرط: استفاده از is_not به‌جای isnot
        conditions.append(MemoryEntry.embedding.is_not(None))
        if service_scope:
            conditions.append(MemoryEntry.service_scope == service_scope)
        
        stmt = (
            select(
                MemoryEntry,
                MemoryEntry.embedding.cosine_distance(query_embedding).label("distance")
            )
            .where(and_(*conditions))
            .order_by("distance")
            .limit(limit)
        )
        
        result = await self.db.execute(stmt)
        rows = result.all()
        
        entries = []
        for row in rows:
            entry = row[0]
            distance = row[1]
            similarity = 1 - distance
            
            if similarity >= min_similarity:
                entries.append({
                    "id": str(entry.id),
                    "pattern": entry.pattern,
                    "symptoms": entry.symptoms,
                    "root_cause": entry.root_cause,
                    "action": entry.action,
                    "verification_result": entry.verification_result,
                    "outcome": entry.outcome,
                    "service_scope": entry.service_scope,
                    "reuse_count": entry.reuse_count,
                    "similarity": float(similarity)
                })
        
        logger.info(f"Memory search returned {len(entries)} similar entries")
        return entries
    
    async def update_reuse_count(self, entry_id: UUID) -> None:
        """افزایش تعداد استفاده‌ی مجدد از یک Memory Entry"""
        stmt = select(MemoryEntry).where(MemoryEntry.id == entry_id)
        result = await self.db.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry:
            # ✅ اصلاح مقداردهی: استفاده از مقدار عددی
            entry.reuse_count = entry.reuse_count + 1  # type: ignore[assignment]
            await self.db.commit()
            logger.info(f"Memory entry {entry_id} reuse count: {entry.reuse_count}")