"""Minimal process entrypoint for a frozen or virtualenv-based on-host VM agent.

Deployment config and secrets are provided via environment, not embedded into
the binary. The API/control-plane application is NOT started in this process.
"""
from __future__ import annotations

import os

import uvicorn

from domain.contracts.config import settings


def main() -> None:
    if settings.MCP_SERVER_PROVIDER != "vm_agent":
        raise RuntimeError("vm_agent_runner_requires_vm_agent_provider")
    if settings.SSH_ENABLED:
        raise RuntimeError("vm_agent_runner_forbids_ssh")
    # An HTTPS, mTLS-capable gateway may expose this loopback listener.
    # Never expose the raw HTTP application on a public interface.
    from apps.mcp_server.main import app
    uvicorn.run(app, host="127.0.0.1",
                port=int(os.environ.get("VM_AGENT_BIND_PORT", "9105")),
                access_log=False, proxy_headers=False)


if __name__ == "__main__":
    main()
