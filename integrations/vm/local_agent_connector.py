"""Compatibility import: the SSH-free agent code lives under vmmcpagent/."""
from vmmcpagent.connector import LocalVMConnector

__all__ = ["LocalVMConnector"]
