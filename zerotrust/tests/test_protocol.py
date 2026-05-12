"""Tests for common.protocol — TCP framing + envelope."""

from __future__ import annotations

import base64
import io
import socket
import struct
import threading

import pytest

from zerotrust.common import protocol
from zerotrust.common.exceptions import ProtocolError


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeSocket:
    """Minimal duck-typed socket that returns scripted bytes from ``recv``."""

    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)

    def recv(self, n: int) -> bytes:
        return self._buf.read(n)


class TruncatingSocket:
    """Returns less than asked for, then EOF, to exercise recvall's loop."""

    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)

    def recv(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        return chunk[:n]


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def test_pack_recv_roundtrip():
    msg = {"hello": "world", "n": 42}
    packed = protocol.pack_message(msg)
    sock = FakeSocket(packed)
    assert protocol.recv_message(sock) == msg


def test_recvall_loops_on_partial_reads():
    msg = {"a": 1}
    packed = protocol.pack_message(msg)
    # Force partial reads: 1 byte at a time
    sock = TruncatingSocket([bytes([b]) for b in packed])
    assert protocol.recv_message(sock) == msg


def test_recv_message_raises_on_eof():
    sock = FakeSocket(b"")
    with pytest.raises(ProtocolError):
        protocol.recv_message(sock)


def test_recv_message_raises_on_short_body():
    # Header says 100 bytes but only 5 follow.
    sock = FakeSocket(struct.pack(">I", 100) + b"hello")
    with pytest.raises(ProtocolError):
        protocol.recv_message(sock)


def test_recv_message_rejects_non_dict_top_level():
    body = b"[1,2,3]"
    sock = FakeSocket(struct.pack(">I", len(body)) + body)
    with pytest.raises(ProtocolError):
        protocol.recv_message(sock)


def test_recv_message_rejects_malformed_json():
    body = b"{not json"
    sock = FakeSocket(struct.pack(">I", len(body)) + body)
    with pytest.raises(ProtocolError):
        protocol.recv_message(sock)


def test_pack_rejects_oversized_message():
    huge = {"x": "a" * (protocol.MAX_MESSAGE_BYTES + 1)}
    with pytest.raises(ProtocolError):
        protocol.pack_message(huge)


def test_recv_message_rejects_oversized_header():
    sock = FakeSocket(struct.pack(">I", protocol.MAX_MESSAGE_BYTES + 1))
    with pytest.raises(ProtocolError):
        protocol.recv_message(sock)


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

def test_make_envelope_has_required_fields():
    env = protocol.make_envelope("HELLO", {"foo": "bar"})
    assert env["type"] == "HELLO"
    assert env["version"] == protocol.PROTOCOL_VERSION
    assert env["payload"] == {"foo": "bar"}
    assert isinstance(env["timestamp"], int)
    nonce = base64.b64decode(env["nonce"])
    assert len(nonce) == 16


def test_make_envelope_rejects_unknown_type():
    with pytest.raises(ProtocolError):
        protocol.make_envelope("NOT_A_REAL_TYPE", {})


def test_validate_envelope_accepts_well_formed():
    env = protocol.make_envelope("HELLO", {"foo": "bar"})
    assert protocol.validate_envelope(env) is env


def test_validate_envelope_rejects_missing_field():
    env = protocol.make_envelope("HELLO", {})
    del env["nonce"]
    with pytest.raises(ProtocolError):
        protocol.validate_envelope(env)


def test_validate_envelope_rejects_short_nonce():
    env = protocol.make_envelope("HELLO", {})
    env["nonce"] = base64.b64encode(b"\x00" * 8).decode("ascii")
    with pytest.raises(ProtocolError):
        protocol.validate_envelope(env)


def test_make_envelope_nonces_are_unique():
    nonces = {protocol.make_envelope("HELLO", {})["nonce"] for _ in range(100)}
    assert len(nonces) == 100


# ---------------------------------------------------------------------------
# Real socket round-trip — make sure the helpers work end-to-end
# ---------------------------------------------------------------------------

def test_real_socket_roundtrip():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    host, port = server_sock.getsockname()

    payload = protocol.make_envelope("HELLO", {"a": 1, "b": [1, 2, 3]})
    received: dict = {}

    def server() -> None:
        conn, _ = server_sock.accept()
        try:
            received.update(protocol.recv_message(conn))
        finally:
            conn.close()

    t = threading.Thread(target=server)
    t.start()
    try:
        with socket.create_connection((host, port)) as client:
            protocol.send_message(client, payload)
    finally:
        t.join(timeout=2)
        server_sock.close()
    assert received["type"] == "HELLO"
    assert received["payload"] == {"a": 1, "b": [1, 2, 3]}
