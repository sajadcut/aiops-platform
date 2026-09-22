from __future__ import annotations

import argparse
import asyncio

from apps.memory_service import OperationalMemoryService
from database import AsyncSessionLocal


async def main(limit: int) -> None:
    async with AsyncSessionLocal() as db:
        count = await OperationalMemoryService(db).mark_stale_entries(limit=limit)
    print({"stale_marked": count})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mark aged Operational Memory episodes stale."
    )
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()
    asyncio.run(main(args.limit))
