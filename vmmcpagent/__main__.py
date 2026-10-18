"""Start the vmmcpagent service with configuration beside the agent.

Both the source checkout and the frozen Linux bundle use the operator-owned
agent.env placed next to this entrypoint/executable. This module deliberately
loads that file before importing the centralized AIOps settings or MCP server.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def agent_directory() -> Path:
    return (Path(sys.executable).resolve().parent if getattr(sys, "frozen", False)
            else Path(__file__).resolve().parent)


def configure_agent_environment() -> Path:
    home = agent_directory()
    configuration = home / "agent.env"
    if configuration.is_symlink():
        raise RuntimeError("vm_agent_config_symlink_forbidden")
    if configuration.exists():
        meta = configuration.stat()
        if not stat.S_ISREG(meta.st_mode):
            raise RuntimeError("vm_agent_config_must_be_regular_file")
        if meta.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise RuntimeError("vm_agent_config_permissions_must_be_0600")
        # systemd can inject an owner=root mode 0600 EnvironmentFile;
        # only read the file here when the unprivileged agent can access it.
        if os.access(configuration, os.R_OK):
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=configuration, override=False)

    # Pydantic Settings' non-secret defaults originate from the repository
    # .env.example in a source checkout, or the copied .env.example in the
    # packaged runtime. No central API .env is needed on target hosts.
    os.chdir(home if getattr(sys, "frozen", False) else home.parent)
    return home


def main() -> None:
    configure_agent_environment()
    from domain.contracts.config import settings
    if settings.MCP_SERVER_PROVIDER != "vm_agent":
        raise RuntimeError("vm_agent_runner_requires_vm_agent_provider")
    if settings.SSH_ENABLED:
        raise RuntimeError("vm_agent_runner_forbids_ssh")
    if not settings.MCP_SERVER_REQUIRE_AUTH:
        raise RuntimeError("vm_agent_runner_requires_authentication")
    if not settings.VM_AGENT_BEARER_TOKEN:
        raise RuntimeError("vm_agent_bearer_token_missing")

    from vmmcpagent.connector import LocalVMConnector
    LocalVMConnector()
    import uvicorn
    from apps.mcp_server.main import app
    # Raw HTTP is always loopback-only. Put an authenticated, TLS-verified
    # reverse proxy in front. No configuration knob can expose this socket.
    port = int(os.environ.get("VM_AGENT_BIND_PORT", "9105"))
    if not 1 <= port <= 65535:
        raise RuntimeError("vm_agent_port_invalid")
    uvicorn.run(app, host="127.0.0.1", port=port,
                access_log=False, proxy_headers=False)


if __name__ == "__main__":
    main()
