"""PDF demo integration tests.

These tests intentionally compose the real CA CLI, TCP server, client
handshake, pubkey lookup, upload, pending listing, download, and recipient-side
decrypt/verify paths. They do not mock crypto or protocol primitives.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from zerotrust.ca import ca as ca_cli
from zerotrust.client.download import (
    download_file,
    list_pending,
    verify_and_decrypt_download,
)
from zerotrust.client.session import connected_session
from zerotrust.client.upload import upload_file
from zerotrust.common.exceptions import CryptoError
from zerotrust.common.origin import sign_origin_struct
from zerotrust.common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from zerotrust.server.main import ZeroTrustRequestHandler, ZeroTrustServer


DEMO_PASSWORD = b"demo-password"


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _bootstrap_ca_and_identities(root: Path) -> None:
    assert ca_cli.main(["init", "--out", "ca_data"]) == 0
    for username in ("server", "alice", "bob"):
        assert ca_cli.main([
            "issue",
            username,
            "--ca-dir",
            "ca_data",
            "--user-dir",
            "users",
        ]) == 0

    pubkeys = root / "zerotrust" / "server" / "storage" / "pubkeys"
    pubkeys.mkdir(parents=True)
    for username in ("alice", "bob"):
        shutil.copyfile(
            root / "users" / username / "cert.json",
            pubkeys / f"{username}.json",
        )


def _write_client_bundle(root: Path, username: str, port: int) -> None:
    client_dir = root / f"client_{username}"
    client_dir.mkdir()
    shutil.copyfile(root / "users" / username / "cert.json", client_dir / "cert.json")
    shutil.copyfile(
        root / "users" / username / "private.pem",
        client_dir / "private.pem",
    )
    shutil.copyfile(root / "ca_data" / "ca_cert.json", client_dir / "ca_cert.json")
    (client_dir / "config.json").write_text(
        json.dumps({
            "username": username,
            "server_host": "127.0.0.1",
            "server_port": port,
            "server_subject": "server",
        }),
        encoding="utf-8",
    )


def _server_state(root: Path) -> dict[str, Any]:
    return {
        "db_path": str(root / "zerotrust" / "server" / "storage" / "metadata.db"),
        "ca_cert_path": str(root / "ca_data" / "ca_cert.json"),
        "cert_path": str(root / "users" / "server" / "cert.json"),
        "key_path": str(root / "users" / "server" / "private.pem"),
        "server_password": DEMO_PASSWORD,
    }


def _wait_until_listening(port: int, timeout: float = 1.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError as exc:
            last_error = exc
    raise AssertionError(f"server did not listen on {port}") from last_error


@contextmanager
def _running_server(root: Path) -> Iterator[int]:
    server = ZeroTrustServer(
        ("127.0.0.1", 0),
        ZeroTrustRequestHandler,
        _server_state(root),
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _wait_until_listening(port)
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        assert not thread.is_alive()


def _fetch_download_payload(session: dict[str, Any], file_id: str) -> dict[str, Any]:
    send_message(session["sock"], make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))
    envelope = validate_envelope(recv_message(session["sock"]))
    assert envelope["type"] == "DOWNLOAD_RESPONSE"
    return envelope["payload"]


def _file_row(root: Path, file_id: str) -> sqlite3.Row:
    conn = sqlite3.connect(root / "zerotrust" / "server" / "storage" / "metadata.db")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM files WHERE file_id = ?",
            (file_id,),
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    return row


def test_pdf_demo_happy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _bootstrap_ca_and_identities(tmp_path)

    original = os.urandom(4096)
    report = tmp_path / "report.pdf"
    report.write_bytes(original)

    with _running_server(tmp_path) as port:
        _write_client_bundle(tmp_path, "alice", port)
        _write_client_bundle(tmp_path, "bob", port)

        with connected_session("alice", DEMO_PASSWORD) as alice:
            assert {
                "peer_subject",
                "peer_cert",
                "c2s_key",
                "s2c_key",
                "transcript_hash",
            }.issubset(alice)
            assert alice["peer_subject"] == "server"
            ack = upload_file(alice, "bob", str(report))

        file_id = ack["file_id"]
        assert isinstance(file_id, str)

        with connected_session("bob", DEMO_PASSWORD) as bob:
            pending = list_pending(bob)
            assert len(pending) == 1
            assert pending[0]["file_id"] == file_id
            output_path = download_file(bob, file_id)

    assert output_path.read_bytes() == original

    row = _file_row(tmp_path, file_id)
    assert row["sender_id"] == "alice"
    assert row["recipient_id"] == "bob"
    assert row["status"] in {"pending", "downloaded"}
    assert (tmp_path / "zerotrust" / "server" / "storage" / "files" / f"{file_id}.bin").is_file()
    assert (tmp_path / "zerotrust" / "server" / "storage" / "pubkeys" / "alice.json").is_file()
    assert (tmp_path / "zerotrust" / "server" / "storage" / "pubkeys" / "bob.json").is_file()


def test_pdf_demo_tampering_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _bootstrap_ca_and_identities(tmp_path)

    report = tmp_path / "report.pdf"
    report.write_bytes(os.urandom(4096))

    with _running_server(tmp_path) as port:
        _write_client_bundle(tmp_path, "alice", port)
        _write_client_bundle(tmp_path, "bob", port)

        with connected_session("alice", DEMO_PASSWORD) as alice:
            ack = upload_file(alice, "bob", str(report))
        file_id = ack["file_id"]

        with connected_session("bob", DEMO_PASSWORD) as bob:
            pending = list_pending(bob)
            assert [row["file_id"] for row in pending] == [file_id]
            payload = _fetch_download_payload(bob, file_id)

            ciphertext = bytearray(base64.b64decode(payload["ciphertext"], validate=True))
            ciphertext[0] ^= 0x01
            payload["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")

            wrapped_key = base64.b64decode(payload["wrapped_key"], validate=True)
            alice_priv = (tmp_path / "users" / "alice" / "private.pem").read_bytes()
            payload["sender_signature"] = base64.b64encode(
                sign_origin_struct(
                    alice_priv,
                    DEMO_PASSWORD,
                    sender="alice",
                    recipient="bob",
                    file_id=file_id,
                    ciphertext_sha256=hashlib.sha256(bytes(ciphertext)).hexdigest(),
                    wrapped_key_sha256=hashlib.sha256(wrapped_key).hexdigest(),
                    timestamp=payload["timestamp"],
                    expiration=payload["expiration"],
                )
            ).decode("ascii")

            with pytest.raises(CryptoError):
                verify_and_decrypt_download(bob, payload, file_id)

    assert not (tmp_path / "client_bob" / "downloads" / file_id).exists()
    assert _load_json(tmp_path / "users" / "alice" / "cert.json")["subject"] == "alice"
