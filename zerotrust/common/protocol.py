"""Wire format and message envelope helpers.

Implements ARCHITECTURE.md §7.1 (length-prefixed JSON framing) and §7.2
(message envelope). All Phase 2/3 code MUST use these functions instead of
re-rolling its own framing or envelope.

Frozen signatures (per ARCHITECTURE.md §10.1):
    pack_message(msg: dict) -> bytes
    recv_message(sock) -> dict
    make_envelope(msg_type: str, payload: dict) -> dict
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import time
import uuid
from typing import Any

from .exceptions import ProtocolError

# 4-byte big-endian unsigned int = max 4 GiB per message; we cap much lower to
# avoid memory abuse. The largest legitimate payload is a chunked file upload,
# which is bounded by application policy (see Phase 2 issue #12).
_LENGTH_HEADER = struct.Struct(">I")
MAX_MESSAGE_BYTES = 64 * 1024 * 1024  # 64 MiB hard ceiling

PROTOCOL_VERSION = 1


# ---------------------------------------------------------------------------
# Low-level framing
# ---------------------------------------------------------------------------

def recvall(sock: socket.socket, n: int) -> bytes:
    """Receive exactly *n* bytes from *sock* or raise ProtocolError.

    Bare ``recv(n)`` is forbidden because TCP may deliver fewer bytes than
    requested. This helper loops until *n* bytes have arrived or the peer
    closes the connection.
    """
    if n < 0:
        raise ValueError("recvall length must be non-negative")
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError(
                f"connection closed after {len(buf)} of {n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def pack_message(msg: dict) -> bytes:
    """Serialise *msg* to wire bytes: ``<4B length><JSON utf-8>``.

    The JSON is compact (no whitespace) but NOT canonical — canonical JSON is
    only required for content that will be signed (see ``canonical.py``).
    """
    if not isinstance(msg, dict):
        raise TypeError("pack_message expects a dict")
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        raise ProtocolError(
            f"message too large: {len(body)} > {MAX_MESSAGE_BYTES}"
        )
    return _LENGTH_HEADER.pack(len(body)) + body


def send_message(sock: socket.socket, msg: dict) -> None:
    """Convenience wrapper: pack + sendall."""
    sock.sendall(pack_message(msg))


def recv_message(sock: socket.socket) -> dict:
    """Read one length-prefixed JSON message from *sock*.

    Raises ProtocolError on framing or parse errors. The decoded object MUST
    be a dict (per envelope contract).
    """
    header = recvall(sock, _LENGTH_HEADER.size)
    (length,) = _LENGTH_HEADER.unpack(header)
    if length > MAX_MESSAGE_BYTES:
        raise ProtocolError(
            f"declared message length {length} exceeds limit {MAX_MESSAGE_BYTES}"
        )
    body = recvall(sock, length)
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"malformed JSON message: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("top-level message must be a JSON object")
    return obj


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

# Set of message types defined in ARCHITECTURE.md §7.3. Phase 2/3 code MUST
# use one of these strings; unknown types are rejected by validate_envelope.
MESSAGE_TYPES = frozenset({
    "HELLO",
    "KEY_EXCHANGE",
    "AUTH_CHALLENGE",
    "AUTH_RESPONSE",
    "SESSION_OK",
    "GET_PUBKEY",
    "PUBKEY_RESPONSE",
    "UPLOAD_REQUEST",
    "UPLOAD_ACK",
    "LIST_PENDING",
    "PENDING_LIST",
    "DOWNLOAD_REQUEST",
    "DOWNLOAD_RESPONSE",
    "DOWNLOAD_ACK",
    "ACK_OK",
    "REVOKE_REQUEST",
    "REVOKE_ACK",
    "ERROR",
})


def make_envelope(msg_type: str, payload: dict) -> dict:
    """Build a fresh envelope per ARCHITECTURE.md §7.2.

    Generates a new 16-byte nonce and unix timestamp every call — never reuse
    an envelope. The caller is responsible for any subsequent encryption.
    """
    if msg_type not in MESSAGE_TYPES:
        raise ProtocolError(f"unknown message type: {msg_type!r}")
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")
    return {
        "type": msg_type,
        "version": PROTOCOL_VERSION,
        "nonce": base64.b64encode(os.urandom(16)).decode("ascii"),
        "timestamp": int(time.time()),
        "request_id": str(uuid.uuid4()),
        "payload": payload,
    }


def validate_envelope(msg: Any) -> dict:
    """Check that *msg* has the required envelope fields. Returns the dict.

    Raises ProtocolError if any required field is missing or malformed. This
    is a structural check only; freshness/replay checks live in ``replay.py``.
    """
    if not isinstance(msg, dict):
        raise ProtocolError("envelope must be a dict")
    required = {"type", "version", "nonce", "timestamp", "request_id", "payload"}
    missing = required - msg.keys()
    if missing:
        raise ProtocolError(f"envelope missing fields: {sorted(missing)}")
    if msg["version"] != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {msg['version']}")
    if msg["type"] not in MESSAGE_TYPES:
        raise ProtocolError(f"unknown message type: {msg['type']!r}")
    if not isinstance(msg["payload"], dict):
        raise ProtocolError("envelope payload must be a dict")
    try:
        nonce = base64.b64decode(msg["nonce"], validate=True)
    except Exception as exc:  # noqa: BLE001 — we re-raise as ProtocolError
        raise ProtocolError(f"envelope nonce not valid base64: {exc}") from exc
    if len(nonce) != 16:
        raise ProtocolError(f"envelope nonce must be 16 bytes, got {len(nonce)}")
    if not isinstance(msg["timestamp"], int):
        raise ProtocolError("envelope timestamp must be an integer")
    return msg
