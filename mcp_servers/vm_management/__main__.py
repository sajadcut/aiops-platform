from __future__ import annotations

import uvicorn

from mcp_servers.vm_management.app import create_app
from mcp_servers.vm_management.config import VMManagementSettings


def main() -> None:
    settings = VMManagementSettings.from_environment()
    uvicorn.run(create_app(settings=settings), host=settings.HOST, port=settings.PORT)


if __name__ == "__main__":
    main()
