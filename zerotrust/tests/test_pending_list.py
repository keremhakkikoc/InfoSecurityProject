from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from zerotrust.client.download import list_pending
from zerotrust.common.protocol import make_envelope, pack_message, recv_message, validate_envelope
from zerotrust.server import handler, store


class FakeSocket:
    def __init__(self, incoming: bytes = b"") -> None:
        self._incoming = bytearray(incoming)
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, n: int) -> bytes:
        if not self._incoming:
            return b""
        chunk = self._incoming[:n]
        del self._incoming[:n]
        return bytes(chunk)


def _row(file_id: str, recipient: str, *, expiration: int | None = None) -> dict[str, Any]:
    now = int(time.time())
    return {
        "file_id": file_id,
        "sender_id": "alice",
        "recipient_id": recipient,
        "upload_timestamp": now,
        "expiration": expiration if expiration is not None else now + 3600,
        "status": "pending",
        "ciphertext_path": f"{file_id}.bin",
        "ciphertext_sha256": "00",
        "wrapped_key": b"wrapped",
        "aes_nonce": b"nonce",
        "aes_aad": b"aad",
        "sender_signature": b"signature",
        "sender_cert_json": "{}",
    }


def _conn() -> sqlite3.Connection:
    conn = store.open_connection(":memory:")
    store.init_schema(conn)
    return conn


def _list_for(conn: sqlite3.Connection, tmp_path: Path, recipient: str) -> dict[str, Any]:
    files_dir = tmp_path / "files"
    files_dir.mkdir(exist_ok=True)
    sock = FakeSocket()
    handler._handle_list_pending(
        sock,
        conn,
        {"peer_subject": recipient},
        {"files_dir": str(files_dir)},
    )
    return validate_envelope(recv_message(FakeSocket(bytes(sock.sent))))


def test_list_pending_returns_metadata_without_sensitive_blobs(tmp_path):
    conn = _conn()
    try:
        store.insert_file(conn, _row("f_bob", "bob"))
        files_dir = tmp_path / "files"
        files_dir.mkdir()
        (files_dir / "f_bob.bin").write_bytes(b"ciphertext")

        reply = _list_for(conn, tmp_path, "bob")
    finally:
        conn.close()

    assert reply["type"] == "PENDING_LIST"
    assert reply["payload"]["files"] == [{
        "file_id": "f_bob",
        "sender_id": "alice",
        "upload_timestamp": reply["payload"]["files"][0]["upload_timestamp"],
        "expiration": reply["payload"]["files"][0]["expiration"],
        "size": len(b"ciphertext"),
    }]
    assert "wrapped_key" not in reply["payload"]["files"][0]
    assert "sender_signature" not in reply["payload"]["files"][0]


def test_list_pending_enforces_recipient_isolation(tmp_path):
    conn = _conn()
    try:
        store.insert_file(conn, _row("f_bob", "bob"))
        reply = _list_for(conn, tmp_path, "carol")
    finally:
        conn.close()

    assert reply["payload"]["files"] == []


def test_list_pending_omits_expired_rows(tmp_path):
    conn = _conn()
    try:
        store.insert_file(conn, _row("f_old", "bob", expiration=int(time.time()) - 1))
        reply = _list_for(conn, tmp_path, "bob")
    finally:
        conn.close()

    assert reply["payload"]["files"] == []


def test_list_pending_can_be_repeated_without_replay_failure(tmp_path):
    conn = _conn()
    try:
        store.insert_file(conn, _row("f_bob", "bob"))
        first = _list_for(conn, tmp_path, "bob")
        second = _list_for(conn, tmp_path, "bob")
    finally:
        conn.close()

    assert first["type"] == "PENDING_LIST"
    assert second["type"] == "PENDING_LIST"
    assert first["payload"]["files"][0]["file_id"] == "f_bob"
    assert second["payload"]["files"][0]["file_id"] == "f_bob"


def test_client_list_pending_sends_request_and_returns_files():
    payload = {"files": [{"file_id": "f1", "sender_id": "alice", "size": 12}]}
    sock = FakeSocket(pack_message(make_envelope("PENDING_LIST", payload)))

    files = list_pending({"sock": sock})

    sent = validate_envelope(recv_message(FakeSocket(bytes(sock.sent))))
    assert sent["type"] == "LIST_PENDING"
    assert sent["payload"] == {}
    assert files == payload["files"]
