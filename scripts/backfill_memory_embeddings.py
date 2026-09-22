from __future__ import annotations

import argparse
import asyncio

from database import AsyncSessionLocal
from apps.memory_service import OperationalMemoryService


async def main(limit: int) -> None:
    async with AsyncSessionLocal() as db:
        result = await OperationalMemoryService(db).backfill_embeddings(limit=limit)
    print(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Backfill pending/failed Operational Memory embeddings."
    )
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    asyncio.run(main(args.limit))
