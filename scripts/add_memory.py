import asyncio
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parent.parent))

from database import AsyncSessionLocal
from apps.memory_service import OperationalMemoryService
from domain.contracts.logging import logger

async def add_sample_memory():
    try:
        async with AsyncSessionLocal() as db:
            service = OperationalMemoryService(db)
            
            entries = [
                {
                    "pattern": "HTTP 500 errors after deployment, resolved by rollback",
                    "symptoms": {"error_rate": 15.0, "http_500": True},
                    "root_cause": "Deployment v2.3.1 introduced database connection timeout",
                    "action": "Rollback to v2.3.0 using kubectl rollout undo",
                    "verification_result": "success",
                    "outcome": "Error rate dropped to 2% within 5 minutes",
                    "environment": "production",
                    "service_scope": "payment-service"
                },
                {
                    "pattern": "Kubernetes pod crash due to missing ConfigMap",
                    "symptoms": {"crash_loop": True, "pod_restarts": 5},
                    "root_cause": "DATABASE_URL environment variable missing in ConfigMap",
                    "action": "Updated ConfigMap and restarted deployment",
                    "verification_result": "success",
                    "outcome": "Pods running stable with 0 restarts",
                    "environment": "production",
                    "service_scope": "payment-service"
                },
                {
                    "pattern": "Debian VM slow due to high memory usage",
                    "symptoms": {"memory_usage": 92.0, "swap_usage": 50.0},
                    "root_cause": "Memory leak in application process",
                    "action": "Restarted application service and increased memory limit",
                    "verification_result": "success",
                    "outcome": "Memory usage dropped to 60% and VM became responsive",
                    "environment": "production",
                    "service_scope": "debian10-vm"
                }
            ]
            
            for entry in entries:
                entry_id = await service.add_entry(
                    pattern=entry["pattern"],
                    symptoms=entry["symptoms"],
                    root_cause=entry["root_cause"],
                    action=entry["action"],
                    verification_result=entry["verification_result"],
                    outcome=entry["outcome"],
                    environment=entry["environment"],
                    service_scope=entry["service_scope"],
                    incident_id=uuid4()
                )
                print(f"✅ Added: {entry['pattern'][:40]}... (ID: {entry_id})")
                
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        logger.error(f"Failed to add memory entries: {str(e)}")

if __name__ == "__main__":
    asyncio.run(add_sample_memory())
    print("🎉 Script finished.")