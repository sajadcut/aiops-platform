import asyncio
import sys
from pathlib import Path

# اضافه کردن مسیر ریشه پروژه به sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.infrastructure.database import AsyncSessionLocal
from app.services.knowledge_rag import KnowledgeRAGService
from app.services.embedding_service import EmbeddingService

async def add_sample_knowledge():
    """افزودن چند سند دانش نمونه"""
    async with AsyncSessionLocal() as db:
        service = KnowledgeRAGService(db)
        
        documents = [
            {
                "title": "Rollback Payment Service",
                "content": "If payment service error rate exceeds 10%, rollback to previous version using kubectl rollout undo deployment/payment-service. Wait 2 minutes and verify error rate drops below 5%.",
                "source": "Runbook #123",
                "version": "1.0",
                "metadata": {"category": "application", "service": "payment-service"}
            },
            {
                "title": "Kubernetes Pod Crash Recovery",
                "content": "When a pod is in CrashLoopBackOff, check logs with kubectl logs <pod-name>. Common causes: missing environment variables, database connection issues, or resource limits. If config issue, update ConfigMap and restart deployment.",
                "source": "Runbook #456",
                "version": "1.2",
                "metadata": {"category": "kubernetes", "service": "payment-service"}
            },
            {
                "title": "High CPU Alert Response",
                "content": "If CPU usage exceeds 80% for 5 minutes, check node status with kubectl describe node. If node is overloaded, scale deployment with kubectl scale deployment <name> --replicas=<count>. Consider adding horizontal pod autoscaler.",
                "source": "Runbook #789",
                "version": "1.0",
                "metadata": {"category": "infrastructure", "service": "payment-service"}
            }
        ]
        
        for doc in documents:
            doc_id = await service.add_document(
                title=doc["title"],
                content=doc["content"],
                source=doc["source"],
                version=doc["version"],
                metadata=doc["metadata"]
            )
            print(f"✅ Added: {doc['title']} (ID: {doc_id})")

if __name__ == "__main__":
    asyncio.run(add_sample_knowledge())
    print("🎉 All sample knowledge documents added!")