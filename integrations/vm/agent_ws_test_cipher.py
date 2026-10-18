"""Mutually authenticated AEAD framing for lab-only ws:// VM Agent transport.

Unlike WSS, HTTP/WebSocket headers remain visible on the network. The extra
pre-shared key is never sent on the wire, so an intercepted Bearer header by
itself cannot authenticate a peer or decrypt command/sudo password frames.
Both peers prove key possession using fresh 256-bit nonces; HKDF derives
session-unique direction-separated AES-256-GCM keys. A strictly monotonic frame
sequence prevents replay inside the session. This is NOT a TLS replacement for
production: no HTTP metadata privacy and no standard PKI identity.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_WIRE_SIZE = 1024 * 1024
PROTOCOL_VERSION = 1


class SecureChannelError(ValueError):
    pass


def _key(hex_value: str | None) -> bytes:
    if not isinstance(hex_value, str) or len(hex_value) != 64:
        raise SecureChannelError("vm_ws_test_psk_required_32_bytes_hex")
    try:
        result = bytes.fromhex(hex_value)
    except ValueError as exc:
        raise SecureChannelError("vm_ws_test_psk_invalid_hex") from exc
    if len(result) != 32:
        raise SecureChannelError("vm_ws_test_psk_invalid_length")
    return result


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, *, length: int) -> bytes:
    if not isinstance(value, str) or len(value) > length * 2:
        raise SecureChannelError("vm_ws_test_invalid_handshake_encoding")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SecureChannelError("vm_ws_test_invalid_handshake_encoding") from exc
    if len(data) != length:
        raise SecureChannelError("vm_ws_test_invalid_handshake_length")
    return data


def _parse(raw: str) -> dict:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_WIRE_SIZE:
        raise SecureChannelError("vm_ws_test_message_too_large")
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise SecureChannelError("vm_ws_test_invalid_json") from exc
    if not isinstance(payload, dict):
        raise SecureChannelError("vm_ws_test_invalid_message")
    return payload


def _proof(key: bytes, role: bytes, target: str, server_nonce: bytes, client_nonce: bytes) -> bytes:
    return hmac.new(key, role + b"\0" + target.encode("utf-8") + b"\0"
                    + server_nonce + client_nonce, hashlib.sha256).digest()


def _session_keys(key: bytes, target: str, server_nonce: bytes, client_nonce: bytes) -> tuple[bytes, bytes]:
    material = HKDF(
        algorithm=hashes.SHA256(), length=64,
        salt=server_nonce + client_nonce,
        info=b"aiops-vm-ws80-aead-v1|" + target.encode("utf-8"),
    ).derive(key)
    return material[:32], material[32:]


@dataclass
class FrameCipher:
    """directional cipher instance with monotonic, implicit AES-GCM nonces."""
    send_key: bytes
    receive_key: bytes
    target: str
    sender: bytes
    recipient: bytes
    send_number: int = 0
    receive_number: int = 0

    def encrypt(self, raw: str) -> str:
        if not isinstance(raw, str):
            raise SecureChannelError("vm_ws_test_text_required")
        if self.send_number >= 2 ** 64 - 1:
            raise SecureChannelError("vm_ws_test_nonce_exhausted")
        seq = self.send_number
        nonce = seq.to_bytes(12, "big")
        ciphertext = AESGCM(self.send_key).encrypt(
            nonce, raw.encode("utf-8"), self.sender + b"|" + self.target.encode())
        self.send_number += 1
        output = json.dumps({"type": "sealed", "version": 1, "seq": seq, "data": _b64(ciphertext)},
                            separators=(",", ":"))
        if len(output.encode("utf-8")) > MAX_WIRE_SIZE:
            raise SecureChannelError("vm_ws_test_message_too_large")
        return output

    def decrypt(self, raw: str) -> str:
        outer = _parse(raw)
        if (outer.get("type") != "sealed" or outer.get("version") != 1
                or type(outer.get("seq")) is not int
                or outer["seq"] != self.receive_number):
            raise SecureChannelError("vm_ws_test_frame_replay_or_out_of_order")
        try:
            blob = base64.b64decode(outer["data"], validate=True)
            plaintext = AESGCM(self.receive_key).decrypt(
                self.receive_number.to_bytes(12, "big"), blob,
                self.recipient + b"|" + self.target.encode())
            decoded = plaintext.decode("utf-8")
        except (KeyError, ValueError, TypeError, UnicodeError) as exc:
            raise SecureChannelError("vm_ws_test_frame_authentication_failed") from exc
        except Exception as exc:
            raise SecureChannelError("vm_ws_test_frame_authentication_failed") from exc
        self.receive_number += 1
        return decoded


async def secure_server(socket, target: str, psk_hex: str):
    """Existing FastAPI WebSocket must already be accepted."""
    key = _key(psk_hex)
    nonce_server = os.urandom(32)
    await socket.send_text(json.dumps({"type": "server_challenge", "version": 1,
                                      "nonce": _b64(nonce_server)}, separators=(",", ":")))
    import asyncio
    response = _parse(await asyncio.wait_for(socket.receive_text(), timeout=10))
    if response.get("type") != "client_proof" or response.get("version") != 1:
        raise SecureChannelError("vm_ws_test_invalid_client_proof")
    nonce_client = _decode(response.get("nonce"), length=32)
    proof_client = _decode(response.get("mac"), length=32)
    if not hmac.compare_digest(
            proof_client, _proof(key, b"client", target, nonce_server, nonce_client)):
        raise SecureChannelError("vm_ws_test_client_authentication_failed")
    await socket.send_text(json.dumps({"type": "server_proof", "version": 1,
                                      "mac": _b64(_proof(key, b"server", target,
                                                        nonce_server, nonce_client))},
                                     separators=(",", ":")))
    server_to_agent, agent_to_server = _session_keys(key, target, nonce_server, nonce_client)
    return SecureServerSocket(socket, FrameCipher(server_to_agent, agent_to_server, target,
                                                   b"server", b"agent"))


async def secure_agent(socket, target: str, psk_hex: str):
    """Agent refuses any credential/command until the server proves PSK."""
    key = _key(psk_hex)
    import asyncio
    challenge = _parse(await asyncio.wait_for(socket.recv(), timeout=10))
    if challenge.get("type") != "server_challenge" or challenge.get("version") != 1:
        raise SecureChannelError("vm_ws_test_invalid_server_challenge")
    nonce_server = _decode(challenge.get("nonce"), length=32)
    nonce_client = os.urandom(32)
    await socket.send(json.dumps({"type": "client_proof", "version": 1,
                                  "nonce": _b64(nonce_client),
                                  "mac": _b64(_proof(key, b"client", target,
                                                     nonce_server, nonce_client))},
                                 separators=(",", ":")))
    proof = _parse(await asyncio.wait_for(socket.recv(), timeout=10))
    if proof.get("type") != "server_proof" or proof.get("version") != 1:
        raise SecureChannelError("vm_ws_test_invalid_server_proof")
    if not hmac.compare_digest(
            _decode(proof.get("mac"), length=32),
            _proof(key, b"server", target, nonce_server, nonce_client)):
        raise SecureChannelError("vm_ws_test_server_authentication_failed")
    server_to_agent, agent_to_server = _session_keys(key, target, nonce_server, nonce_client)
    return SecureAgentSocket(socket, FrameCipher(agent_to_server, server_to_agent, target,
                                                 b"agent", b"server"))


class SecureServerSocket:
    def __init__(self, socket, cipher: FrameCipher):
        self.socket = socket
        self.cipher = cipher

    async def receive_text(self):
        return self.cipher.decrypt(await self.socket.receive_text())

    async def send_text(self, value: str):
        await self.socket.send_text(self.cipher.encrypt(value))

    async def close(self, **kwargs):
        await self.socket.close(**kwargs)


class SecureAgentSocket:
    def __init__(self, socket, cipher: FrameCipher):
        self.socket = socket
        self.cipher = cipher

    async def send(self, value: str):
        await self.socket.send(self.cipher.encrypt(value))

    async def close(self, **kwargs):
        await self.socket.close(**kwargs)

    def __aiter__(self):
        async def messages():
            async for value in self.socket:
                yield self.cipher.decrypt(value)
        return messages()
