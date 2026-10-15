"""Encrypted, hash-bound, expiring complete-file LLM candidates on the VM MCP worker.

Only the MCP worker may load plaintext; APIs/checkpoints/audit receive hashes.
Use a purpose-separated subkey of the existing MCP_BEARER_TOKEN. No extra secret.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from apps.config_change_authorization import candidate_encryption_key
from integrations.vm.windows_secure_acl import ensure_private_windows_acl

_TTL_SECONDS = 24 * 3600
_MAX_BYTES = 48 * 1024
_SHA = re.compile(r"[a-f0-9]{64}\Z")


class CandidateUnavailable(ValueError):
    """Expected configuration/storage refusal. Never embed sensitive bytes."""


def _key() -> bytes:
    """Only the existing MCP_BEARER_TOKEN is required. Never log key material."""
    try:
        return candidate_encryption_key()
    except PermissionError:
        raise CandidateUnavailable("candidate_mcp_bearer_missing_or_weak") from None


def _default_directory() -> Path:
    """Fixed OS-specific private location, no additional runtime setting."""
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AIOps" / "config-candidates"
    return Path("/var/lib/aiops/config-candidates")


def _directory() -> Path:
    path = _default_directory()
    if not path.is_absolute() or ".." in path.parts:
        raise CandidateUnavailable("candidate_directory_invalid")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        current = path.lstat()
        if not stat.S_ISDIR(current.st_mode):
            raise CandidateUnavailable("candidate_directory_permissions")
        if os.name == "nt":
            ensure_private_windows_acl(str(path))
        elif current.st_uid != os.geteuid() or current.st_mode & 0o077:
            raise CandidateUnavailable("candidate_directory_permissions")
    except PermissionError:
        raise CandidateUnavailable("candidate_directory_permissions") from None
    except OSError:
        raise CandidateUnavailable("candidate_directory_unavailable") from None
    return path


def _binding(*, target: str, service: str, path: str,
             source_hash: str, candidate_hash: str) -> bytes:
    if not all(isinstance(x, str) and x for x in (target, service, path)):
        raise CandidateUnavailable("candidate_binding_incomplete")
    if not _SHA.fullmatch(source_hash) or not _SHA.fullmatch(candidate_hash):
        raise CandidateUnavailable("candidate_hash_invalid")
    return json.dumps({
        "target": target, "service": service.lower().removesuffix(".service"),
        "path": path, "source": source_hash, "candidate": candidate_hash,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _filename(binding: bytes) -> str:
    return hashlib.sha256(b"aiops/config-candidate/v1:" + binding).hexdigest() + ".sealed"


def _read_file(path: Path) -> bytes:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * _MAX_BYTES + 128:
                raise CandidateUnavailable("candidate_file_permissions")
            if os.name == "nt":
                ensure_private_windows_acl(str(path))
            elif info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise CandidateUnavailable("candidate_file_permissions")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read(2 * _MAX_BYTES + 129)
        finally:
            os.close(fd)
    except PermissionError:
        raise CandidateUnavailable("candidate_file_permissions") from None
    except (OSError, ValueError):
        raise CandidateUnavailable("candidate_not_available") from None


def _prune_expired(directory: Path) -> None:
    """Opportunistic bounded ciphertext retention, never touch unknown files."""
    now = int(time.time())
    try:
        examined = 0
        for path in directory.iterdir():
            if examined >= 128:
                break
            if not re.fullmatch(r"[0-9a-f]{64}\.sealed", path.name):
                continue
            examined += 1
            try:
                data = _read_file(path)
                if len(data) < 24 or data[:4] != b"AIC1":
                    continue
                stamp = int.from_bytes(data[4:12], "big")
                if 0 < stamp < now and now - stamp > 2 * _TTL_SECONDS:
                    path.unlink(missing_ok=True)
            except (OSError, CandidateUnavailable):
                continue
    except OSError:
        pass  # retention failure never becomes evidence of validated repair


def store_candidate(*, target: str, service: str, path: str,
                    source_hash: str, candidate_hash: str, candidate: str) -> dict:
    """Seal the exact complete response, durably. Never return its bytes."""
    if not isinstance(candidate, str):
        raise CandidateUnavailable("candidate_not_utf8")
    raw = candidate.encode("utf-8")
    if not 0 < len(raw) <= _MAX_BYTES or hashlib.sha256(raw).hexdigest() != candidate_hash:
        raise CandidateUnavailable("candidate_hash_mismatch")
    binding = _binding(target=target, service=service, path=path,
                       source_hash=source_hash, candidate_hash=candidate_hash)
    directory = _directory()
    key = _key()
    _prune_expired(directory)
    filename = directory / _filename(binding)
    stamp = int(time.time()).to_bytes(8, "big")
    nonce = os.urandom(12)
    sealed = b"AIC1" + stamp + nonce + AESGCM(key).encrypt(
        nonce, raw, binding + stamp)
    try:
        fd = os.open(str(filename), os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        # Same hash-bound contents may be requested again after expiry.
        # Refresh through a private temporary file and atomic rename; never
        # make expired candidates permanently unrepairable without admin
        # intervention. Concurrent refreshes can only commit the SAME bytes
        # and exactly the same sealed identity.
        try:
            existing = load_candidate(target=target, service=service, path=path,
                                      source_hash=source_hash,
                                      candidate_hash=candidate_hash)
        except CandidateUnavailable as exc:
            if str(exc) != "candidate_expired":
                raise
            _read_file(filename)  # refuse to replace an unsafe file/symlink
            temporary = filename.with_name(filename.name + "." +
                                            os.urandom(8).hex() + ".tmp")
            try:
                temp_fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL |
                                  os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(temp_fd, "wb") as stream:
                    stream.write(sealed)
                    stream.flush()
                    os.fsync(stream.fileno())
                if os.name == "nt":
                    ensure_private_windows_acl(str(temporary))
                os.replace(temporary, filename)
            except (OSError, PermissionError):
                raise CandidateUnavailable("candidate_storage_unavailable") from None
            finally:
                temporary.unlink(missing_ok=True)
            return {"candidate_stored": True, "candidate_ttl_seconds": _TTL_SECONDS}
        if existing != candidate:
            raise CandidateUnavailable("candidate_storage_conflict")
        return {"candidate_stored": True, "candidate_ttl_seconds": _TTL_SECONDS}
    except OSError:
        raise CandidateUnavailable("candidate_storage_unavailable") from None
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(sealed)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            ensure_private_windows_acl(str(filename))
    except (OSError, PermissionError):
        filename.unlink(missing_ok=True)
        raise CandidateUnavailable("candidate_storage_unavailable") from None
    return {"candidate_stored": True, "candidate_ttl_seconds": _TTL_SECONDS}


def load_candidate(*, target: str, service: str, path: str,
                   source_hash: str, candidate_hash: str) -> str:
    binding = _binding(target=target, service=service, path=path,
                       source_hash=source_hash, candidate_hash=candidate_hash)
    filename = _directory() / _filename(binding)
    key = _key()
    data = _read_file(filename)
    if len(data) < 40 or data[:4] != b"AIC1":
        raise CandidateUnavailable("candidate_storage_corrupted")
    stamp = data[4:12]
    created = int.from_bytes(stamp, "big")
    now = int(time.time())
    if created > now + 60 or now - created >= _TTL_SECONDS:
        raise CandidateUnavailable("candidate_expired")
    try:
        raw = AESGCM(key).decrypt(data[12:24], data[24:], binding + stamp)
        if not 0 < len(raw) <= _MAX_BYTES or hashlib.sha256(raw).hexdigest() != candidate_hash:
            raise CandidateUnavailable("candidate_hash_mismatch")
        return raw.decode("utf-8", "strict")
    except (InvalidTag, ValueError, UnicodeError):
        raise CandidateUnavailable("candidate_decryption_failed") from None
