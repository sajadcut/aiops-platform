"""Native Windows candidate directory ACL acceptance without external packages.

Run on a real Windows CI runner. This tests Win32 DACL hardening,
inheritance onto encrypted candidate files and fail-closed ACL verification.
It never touches the production candidate directory.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

from integrations.vm.windows_secure_acl import (
    ensure_private_windows_acl, harden_private_windows_acl,
)


@unittest.skipUnless(os.name == "nt", "requires Windows security APIs / NTFS")
class WindowsCandidateAclAcceptance(unittest.TestCase):
    def test_protected_directory_and_new_child_file(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / "AIOps" / "config-candidates"
            directory.mkdir(parents=True)
            harden_private_windows_acl(str(directory))
            ensure_private_windows_acl(str(directory))

            candidate = directory / "smoke.sealed"
            candidate.write_bytes(b"opaque-nonsecret-smoke-test")
            ensure_private_windows_acl(str(candidate))

            # Idempotent; hardening must never relax the DACL.
            harden_private_windows_acl(str(directory))
            ensure_private_windows_acl(str(directory))
            ensure_private_windows_acl(str(candidate))


if __name__ == "__main__":
    unittest.main()
