"""End-to-end upload tests for Phase 2 issue #12."""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.handshake import perform_client_handshake
from zerotrust.client.upload import upload_file
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import ProtocolError
from zerotrust.server.handler import serve_connection
from zerotrust.server import store


PASSWORD = b"upload-test-password"


class _UploadServer:
    def __init__(self, state: dict[str, Any]):
        self.state = state
        self.error: BaseException | None = None
        self.thread: threading.Thread | None = None
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.bind(("127.0.0.1", 0))
        self.listen_sock.listen(1)
        self.port = self.listen_sock.getsockname()[1]

    def __enter__(self) -> "_UploadServer":
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def _run(self) -> None:
        try:
            conn, addr = self.listen_sock.accept()
            serve_connection(conn, addr, self.state)
        except BaseException as exc:  # noqa: BLE001 - test plumbing
            self.error = exc

    def join(self, timeout: float = 3.0) -> None:
        if self.thread is not None:
            self.thread.join(timeout=timeout)

    def __exit__(self, *_exc: object) -> None:
        try:
            self.listen_sock.close()
        except OSError:
            pass


@pytest.fixture()
def upload_env(tmp_path: Path) -> dict[str, Any]:
    ca_priv, ca_pub = cp.generate_rsa_keypair(PASSWORD)
    server_priv, server_pub = cp.generate_rsa_keypair(PASSWORD)
    alice_priv, alice_pub = cp.generate_rsa_keypair(PASSWORD)
    bob_priv, bob_pub = cp.generate_rsa_keypair(PASSWORD)

    server_cert = cert_mod.issue_certificate("server-01", server_pub, ca_priv, PASSWORD)
    alice_cert = cert_mod.issue_certificate("alice", alice_pub, ca_priv, PASSWORD)
    bob_cert = cert_mod.issue_certificate("bob", bob_pub, ca_priv, PASSWORD)

    storage = tmp_path / "server" / "storage"
    pubkeys = storage / "pubkeys"
    files = storage / "files"
    pubkeys.mkdir(parents=True)
    files.mkdir()
    (pubkeys / "bob.json").write_text(json.dumps(bob_cert), encoding="utf-8")

    return {
        "ca_pub": ca_pub,
        "server_priv": server_priv,
        "server_cert": server_cert,
        "alice_priv": alice_priv,
        "alice_cert": alice_cert,
        "bob_priv": bob_priv,
        "bob_cert": bob_cert,
        "state": {
            "db_path": str(storage / "metadata.db"),
            "storage_dir": str(storage),
            "pubkeys_dir": str(pubkeys),
            "files_dir": str(files),
            "server_cert": server_cert,
            "server_priv_pem": server_priv,
            "server_password": PASSWORD,
            "ca_pubkey_pem": ca_pub,
        },
        "files_dir": files,
        "db_path": storage / "metadata.db",
    }


def _client_session(port: int, env: dict[str, Any]) -> tuple[socket.socket, dict[str, Any]]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    state = perform_client_handshake(
        sock=sock,
        client_cert=env["alice_cert"],
        client_priv_pem=env["alice_priv"],
        client_password=PASSWORD,
        ca_pubkey_pem=env["ca_pub"],
        expected_server_subject="server-01",
    )
    live_state = dict(state)
    live_state.update(
        {
            "sock": sock,
            "username": "alice",
            "client_cert": env["alice_cert"],
            "client_priv_pem": env["alice_priv"],
            "client_password": PASSWORD,
            "ca_pubkey_pem": env["ca_pub"],
        }
    )
    return sock, live_state


def test_upload_happy_path_writes_ciphertext_and_metadata(
    tmp_path: Path,
    upload_env: dict[str, Any],
):
    plaintext_path = tmp_path / "message.txt"
    plaintext_path.write_text("secret for bob", encoding="utf-8")

    with _UploadServer(upload_env["state"]) as server:
        sock, session = _client_session(server.port, upload_env)
        try:
            ack = upload_file(session, "bob", str(plaintext_path), expiration_seconds=3600)
        finally:
            sock.close()
        server.join()

    assert server.error is None
    file_id = ack["file_id"]
    stored_path = upload_env["files_dir"] / f"{file_id}.bin"
    assert stored_path.is_file()
    assert stored_path.read_bytes() != plaintext_path.read_bytes()

    conn = store.open_connection(str(upload_env["db_path"]))
    try:
        row = store.get_file(conn, file_id)
    finally:
        conn.close()
    assert row is not None
    assert row["sender_id"] == "alice"
    assert row["recipient_id"] == "bob"
    assert row["ciphertext_sha256"]


def test_missing_recipient_cert_returns_not_found(
    tmp_path: Path,
    upload_env: dict[str, Any],
):
    plaintext_path = tmp_path / "message.txt"
    plaintext_path.write_text("secret for nobody", encoding="utf-8")

    (Path(upload_env["state"]["pubkeys_dir"]) / "bob.json").unlink()
    with _UploadServer(upload_env["state"]) as server:
        sock, session = _client_session(server.port, upload_env)
        try:
            with pytest.raises(ProtocolError, match="NOT_FOUND"):
                upload_file(session, "bob", str(plaintext_path), expiration_seconds=3600)
        finally:
            sock.close()
        server.join()

    assert list(upload_env["files_dir"].glob("*.bin")) == []


def test_missing_file_refuses_before_network(tmp_path: Path, monkeypatch):
    session = {"sock": object()}

    def fail_fetch(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise AssertionError("network should not be reached")

    monkeypatch.setattr("zerotrust.client.upload.fetch_peer_cert", fail_fetch)
    with pytest.raises(FileNotFoundError, match="FILE_NOT_FOUND"):
        upload_file(session, "bob", str(tmp_path / "missing.txt"))


def test_file_too_big_refuses_before_network(tmp_path: Path, monkeypatch):
    big_file = tmp_path / "too-big.bin"
    big_file.write_bytes(b"123456789")
    session = {"sock": object()}

    def fail_fetch(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise AssertionError("network should not be reached")

    monkeypatch.setattr("zerotrust.client.upload.MAX_MESSAGE_BYTES", 8)
    monkeypatch.setattr("zerotrust.client.upload.fetch_peer_cert", fail_fetch)
    with pytest.raises(ProtocolError, match="MESSAGE_TOO_LARGE"):
        upload_file(session, "bob", str(big_file))
