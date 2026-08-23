from typing import List
import numpy as np
import hashlib
import random
from app.core.logging import logger

class EmbeddingService:
    """
    سرویس تولید Embedding برای متن‌ها.
    در MVP از Mock استفاده می‌کند، بعداً با مدل‌های واقعی جایگزین می‌شود.
    """
    
    @staticmethod
    async def generate_embedding(text: str) -> List[float]:
        """تولید Embedding برای یک متن (Mock)"""
        # تولید یک بردار ثابت بر اساس هش متن (برای تکرارپذیری)
        hash_val = int(hashlib.md5(text.encode()).hexdigest(), 16)
        random.seed(hash_val)
        embedding = [random.random() for _ in range(1536)]
        
        # نرمال‌سازی (برای شباهت کسینوسی)
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = [v / norm for v in embedding]
        
        logger.info(f"Generated embedding for text length: {len(text)}")
        return embedding
    
    @staticmethod
    async def generate_embeddings(texts: List[str]) -> List[List[float]]:
        """تولید Embedding برای لیستی از متون"""
        embeddings = []
        for text in texts:
            emb = await EmbeddingService.generate_embedding(text)
            embeddings.append(emb)
        return embeddings