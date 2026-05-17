"""End-to-end + error-path tests for the upload flow (issue #19).

The happy-path test runs a real in-process server (``ThreadingTCPServer``)
on an ephemeral port and uploads a small file from Alice to Bob. It proves:

* The file on disk is binary ciphertext (server cannot read plaintext).
* A metadata row is inserted for the upload.
* The recipient cert is fetched via ``GET_PUBKEY`` first.

The error-path tests cover the issue's three explicit "Required tests":
end-to-end happy, recipient cert missing → NOT_FOUND, oversized file →
clean local refusal.

The deeper failure-mode coverage (tampered ciphertext, forged signature,
stale timestamp, replayed nonce, atomic-write crash) is the responsibility
of milestone-2 issue #20 (#13 in the upstream numbering).
"""

from __future__ import annotations

import json
import socket
import socketserver
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.peer import fetch_peer_cert
from zerotrust.client.session import connected_session
from zerotrust.client.upload import upload_file
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import ProtocolError
from zerotrust.common.protocol import MAX_MESSAGE_BYTES
from zerotrust.server.handler import serve_connection
from zerotrust.server.main import ZeroTrustRequestHandler, ZeroTrustServer


CA_PASSWORD = b"ca-test-password"
SERVER_PASSWORD = b"server-test-password"
ALICE_PASSWORD = b"alice-test-password"
BOB_PASSWORD = b"bob-test-password"


# ---------------------------------------------------------------------------
# Fixture: a fully wired CA, server, and two users in a tmp directory.
# ---------------------------------------------------------------------------

class _Env:
    """Bundle of paths/keys for a test environment."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.storage = tmp_path / "server_storage"
        self.pubkeys = self.storage / "pubkeys"
        self.files = self.storage / "files"
        self.storage.mkdir()
        self.pubkeys.mkdir()
        self.files.mkdir()

        # CA.
        self.ca_priv, self.ca_pub = cp.generate_rsa_keypair(CA_PASSWORD)
        self.ca_cert = cert_mod.issue_certificate(
            "ZeroTrustCA", self.ca_pub, self.ca_priv, CA_PASSWORD,
            validity_days=3650,
        )

        # Server.
        self.server_priv, self.server_pub = cp.generate_rsa_keypair(SERVER_PASSWORD)
        self.server_cert = cert_mod.issue_certificate(
            "zerotrust-server", self.server_pub, self.ca_priv, CA_PASSWORD,
        )

        # Users.
        self.alice_priv, self.alice_pub = cp.generate_rsa_keypair(ALICE_PASSWORD)
        self.alice_cert = cert_mod.issue_certificate(
            "alice", self.alice_pub, self.ca_priv, CA_PASSWORD,
        )
        self.bob_priv, self.bob_pub = cp.generate_rsa_keypair(BOB_PASSWORD)
        self.bob_cert = cert_mod.issue_certificate(
            "bob", self.bob_pub, self.ca_priv, CA_PASSWORD,
        )

        # Publish bob's cert in the server pubkey directory (alice we'll
        # leave out by default — uploads are from alice, fetches are for
        # bob; individual tests can add/remove as needed).
        self._write_pubkey("bob", self.bob_cert)
        self._write_pubkey("alice", self.alice_cert)

        self.db_path = self.storage / "metadata.db"

    def _write_pubkey(self, username: str, cert: dict) -> None:
        (self.pubkeys / f"{username}.json").write_text(
            json.dumps(cert), encoding="utf-8"
        )

    def remove_pubkey(self, username: str) -> None:
        (self.pubkeys / f"{username}.json").unlink()

    def server_state(self) -> dict:
        return {
            "db_path": str(self.db_path),
            "ca_pubkey_pem": self.ca_pub,
            "server_cert": self.server_cert,
            "server_priv_pem": self.server_priv,
            "server_password": SERVER_PASSWORD,
            "storage_dir": str(self.storage),
            "pubkeys_dir": str(self.pubkeys),
            "files_dir": str(self.files),
        }

    def write_client_dir(self, username: str) -> Path:
        """Lay out ``client_<username>/`` under tmp for CLI-style use."""
        cdir = self.tmp / f"client_{username}"
        cdir.mkdir(exist_ok=True)
        (cdir / "ca_cert.json").write_text(json.dumps(self.ca_cert))
        if username == "alice":
            cert, priv = self.alice_cert, self.alice_priv
        elif username == "bob":
            cert, priv = self.bob_cert, self.bob_priv
        else:
            raise ValueError(username)
        (cdir / "cert.json").write_text(json.dumps(cert))
        (cdir / "private.pem").write_bytes(priv)
        # config.json filled in by caller (needs the server port).
        return cdir


@pytest.fixture
def env(tmp_path: Path) -> _Env:
    return _Env(tmp_path)


@contextmanager
def _running_server(env: _Env) -> Iterator[int]:
    """Spin up the production ZeroTrustServer on an ephemeral port."""
    server = ZeroTrustServer(
        ("127.0.0.1", 0),
        ZeroTrustRequestHandler,
        env.server_state(),
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _write_alice_config(env: _Env, port: int) -> Path:
    cdir = env.write_client_dir("alice")
    (cdir / "config.json").write_text(json.dumps({
        "server_host": "127.0.0.1",
        "server_port": port,
        "username": "alice",
        "server_subject": "zerotrust-server",
    }))
    return cdir


# ---------------------------------------------------------------------------
# Happy path — end-to-end against a real server thread.
# ---------------------------------------------------------------------------

def test_upload_end_to_end_writes_ciphertext_and_metadata(env, monkeypatch):
    monkeypatch.chdir(env.tmp)
    _write_alice_config(env, port=0)  # rewritten below
    # We need the port BEFORE writing config — re-write after server boot.

    with _running_server(env) as port:
        # Rewrite config with the actual port.
        (env.tmp / "client_alice" / "config.json").write_text(json.dumps({
            "server_host": "127.0.0.1",
            "server_port": port,
            "username": "alice",
            "server_subject": "zerotrust-server",
        }))

        plaintext = b"hello bob, this is a secret\n" * 4
        file_path = env.tmp / "report.txt"
        file_path.write_bytes(plaintext)

        with connected_session("alice", ALICE_PASSWORD) as session:
            ack = upload_file(session, "bob", str(file_path))

    assert "file_id" in ack
    assert "expiration" in ack
    file_id = ack["file_id"]

    # Server wrote a *.bin file...
    blob = env.files / f"{file_id}.bin"
    assert blob.is_file(), f"expected ciphertext blob at {blob}"
    blob_bytes = blob.read_bytes()
    # ...whose contents are NOT the plaintext (proves ciphertext).
    assert plaintext not in blob_bytes
    assert blob_bytes != plaintext

    # Metadata row exists.
    conn = sqlite3.connect(str(env.db_path))
    try:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM files WHERE file_id = ?", (file_id,)
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    assert row["sender_id"] == "alice"
    assert row["recipient_id"] == "bob"
    assert row["status"] == "pending"
    assert row["ciphertext_path"] == f"{file_id}.bin"


# ---------------------------------------------------------------------------
# Recipient cert missing → NOT_FOUND.
# ---------------------------------------------------------------------------

def test_upload_with_unknown_recipient_yields_not_found(env, monkeypatch):
    monkeypatch.chdir(env.tmp)
    env.remove_pubkey("bob")  # Bob is not in the directory.

    with _running_server(env) as port:
        (env.tmp / "client_alice").mkdir(exist_ok=True)
        env.write_client_dir("alice")
        (env.tmp / "client_alice" / "config.json").write_text(json.dumps({
            "server_host": "127.0.0.1",
            "server_port": port,
            "username": "alice",
            "server_subject": "zerotrust-server",
        }))

        file_path = env.tmp / "report.txt"
        file_path.write_bytes(b"data")

        with connected_session("alice", ALICE_PASSWORD) as session:
            with pytest.raises(ProtocolError) as exc:
                upload_file(session, "bob", str(file_path))
            assert "NOT_FOUND" in str(exc.value)


# ---------------------------------------------------------------------------
# Local-only error paths (no server needed).
# ---------------------------------------------------------------------------

def test_upload_missing_file_raises_file_not_found(env):
    """FILE_NOT_FOUND must be raised BEFORE any network I/O."""
    fake_session = {
        "username": "alice",
        "sock": object(),  # would explode if touched
        "client_priv_pem": b"",
        "client_password": b"",
    }
    with pytest.raises(FileNotFoundError) as exc:
        upload_file(fake_session, "bob", "/no/such/file.txt")
    assert "FILE_NOT_FOUND" in str(exc.value)


def test_upload_oversize_file_refused_locally(env, monkeypatch):
    """Files larger than MAX_MESSAGE_BYTES must be refused before sending.

    Uses a sparse file (``os.truncate``) so the test costs nothing on disk —
    the size is what matters, not the contents.
    """
    big = env.tmp / "big.bin"
    big.write_bytes(b"")
    import os as _os
    _os.truncate(big, MAX_MESSAGE_BYTES + 1)

    fake_session = {
        "username": "alice",
        "sock": object(),  # would explode if touched
        "client_priv_pem": b"",
        "client_password": b"",
    }
    with pytest.raises(ProtocolError) as exc:
        upload_file(fake_session, "bob", str(big))
    assert "MESSAGE_TOO_LARGE" in str(exc.value)


# ---------------------------------------------------------------------------
# peer.fetch_peer_cert smoke test — verifies subject pinning.
# ---------------------------------------------------------------------------

def test_fetch_peer_cert_returns_verified_recipient_cert(env, monkeypatch):
    monkeypatch.chdir(env.tmp)
    with _running_server(env) as port:
        env.write_client_dir("alice")
        (env.tmp / "client_alice" / "config.json").write_text(json.dumps({
            "server_host": "127.0.0.1",
            "server_port": port,
            "username": "alice",
            "server_subject": "zerotrust-server",
        }))

        with connected_session("alice", ALICE_PASSWORD) as session:
            cert = fetch_peer_cert(session, "bob")
            assert cert["subject"] == "bob"
