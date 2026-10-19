"""OS-specific VM adapters are lazy: Windows ACL tools must not import SSH.

Importing integrations.vm.windows_secure_acl or config_candidate_vault
must not require the Linux SSH connector and its optional asyncssh runtime.
"""


def __getattr__(name: str):
    if name == "SSHVMConnector":
        from integrations.vm.ssh_connector import SSHVMConnector
        return SSHVMConnector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["SSHVMConnector"]
