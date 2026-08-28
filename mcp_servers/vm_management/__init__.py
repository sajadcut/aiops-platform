"""Production-oriented VM Management MCP Server.

This package is a deployment boundary: only it may hold VM credentials or open
SSH sessions. The AIOps Control Plane talks to it exclusively over MCP.
"""

from .app import create_app

__all__ = ["create_app"]
