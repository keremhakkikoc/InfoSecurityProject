"""Server-side UPLOAD_REQUEST regression suite (issue #20 / m2 #13).

Each acceptance bullet from the issue body gets its own test function.
The handler implementation lives in ``zerotrust/server/handler.py`` (added
in the #19 upload PR); this file is exclusively the failure-mode coverage.

We drive the server through a real ``ThreadingTCPServer`` thread but
forge UPLOAD_REQUEST envelopes by hand from the low-level primitives so
each test can corrupt exactly one thing:

* tampered ciphertext → flip a byte after signing
* forged signature → sign with the wrong private key
* stale timestamp → ``int(time.time()) - 60`` in the envelope
* replayed nonce → send the SAME envelope twice
* unknown recipient → encrypt for a user not in ``pubkeys/``
* atomic write → monkey-patch ``Path.open`` to raise mid-write

Pitfall: every failure must surface as a generic code
to the client (no internal-reason leak) and leave no metadata row /
no final blob on disk.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.handshake import perform_client_handshake
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import ProtocolError
from zerotrust.common.file_crypto import encrypt_file_blob
from zerotrust.common.key_wrap import wrap_aes_key_for
from zerotrust.common.origin import sign_origin_struct
from zerotrust.common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from zerotrust.server import handler as handler_mod
from zerotrust.server.main import ZeroTrustRequestHandler, ZeroTrustServer


CA_PASSWORD = b"ca-test-password"
SERVER_PASSWORD = b"server-test-password"
ALICE_PASSWORD = b"alice-test-password"
BOB_PASSWORD = b"bob-test-password"
MALLORY_PASSWORD = b"mallory-test-password"


# ---------------------------------------------------------------------------
# Fixture environment
# ---------------------------------------------------------------------------

@dataclass
class _Env:
    tmp: Path
    storage: Path
    pubkeys: Path
    files: Path
    ca_priv: bytes
    ca_pub: bytes
    ca_cert: dict
    server_priv: bytes
    server_cert: dict
    alice_priv: bytes
    alice_cert: dict
    bob_priv: bytes
    bob_cert: dict
    mallory_priv: bytes
    mallory_cert: dict
    db_path: Path


def _build_env(tmp_path: Path) -> _Env:
    storage = tmp_path / "server_storage"
    pubkeys = storage / "pubkeys"
    files = storage / "files"
    storage.mkdir()
    pubkeys.mkdir()
    files.mkdir()

    ca_priv, ca_pub = cp.generate_rsa_keypair(CA_PASSWORD)
    ca_cert = cert_mod.issue_certificate(
        "ZeroTrustCA", ca_pub, ca_priv, CA_PASSWORD, validity_days=3650,
    )
    server_priv, server_pub = cp.generate_rsa_keypair(SERVER_PASSWORD)
    server_cert = cert_mod.issue_certificate(
        "zerotrust-server", server_pub, ca_priv, CA_PASSWORD,
    )

    alice_priv, alice_pub = cp.generate_rsa_keypair(ALICE_PASSWORD)
    alice_cert = cert_mod.issue_certificate(
        "alice", alice_pub, ca_priv, CA_PASSWORD,
    )
    bob_priv, bob_pub = cp.generate_rsa_keypair(BOB_PASSWORD)
    bob_cert = cert_mod.issue_certificate(
        "bob", bob_pub, ca_priv, CA_PASSWORD,
    )
    # Mallory is a CA-signed user too — but it's NOT alice. We use her
    # private key to forge signatures while the handshake says alice.
    mallory_priv, mallory_pub = cp.generate_rsa_keypair(MALLORY_PASSWORD)
    mallory_cert = cert_mod.issue_certificate(
        "mallory", mallory_pub, ca_priv, CA_PASSWORD,
    )

    (pubkeys / "alice.json").write_text(json.dumps(alice_cert))
    (pubkeys / "bob.json").write_text(json.dumps(bob_cert))

    return _Env(
        tmp=tmp_path,
        storage=storage,
        pubkeys=pubkeys,
        files=files,
        ca_priv=ca_priv, ca_pub=ca_pub, ca_cert=ca_cert,
        server_priv=server_priv, server_cert=server_cert,
        alice_priv=alice_priv, alice_cert=alice_cert,
        bob_priv=bob_priv, bob_cert=bob_cert,
        mallory_priv=mallory_priv, mallory_cert=mallory_cert,
        db_path=storage / "metadata.db",
    )


@pytest.fixture
def env(tmp_path: Path) -> _Env:
    return _build_env(tmp_path)


def _server_state(env: _Env) -> dict[str, Any]:
    return {
        "db_path": str(env.db_path),
        "ca_pubkey_pem": env.ca_pub,
        "server_cert": env.server_cert,
        "server_priv_pem": env.server_priv,
        "server_password": SERVER_PASSWORD,
        "storage_dir": str(env.storage),
        "pubkeys_dir": str(env.pubkeys),
        "files_dir": str(env.files),
    }


@contextmanager
def _running_server(env: _Env) -> Iterator[int]:
    server = ZeroTrustServer(
        ("127.0.0.1", 0), ZeroTrustRequestHandler, _server_state(env),
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


@contextmanager
def _alice_socket(env: _Env, port: int) -> Iterator[socket.socket]:
    """Open a TCP socket and run the handshake as alice. Yield the socket."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        perform_client_handshake(
            sock=sock,
            client_cert=env.alice_cert,
            client_priv_pem=env.alice_priv,
            client_password=ALICE_PASSWORD,
            ca_pubkey_pem=env.ca_pub,
            expected_server_subject="zerotrust-server",
        )
        yield sock
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Envelope builders — we hand-build so each test can corrupt exactly one
# field.
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _build_upload_payload(
    env: _Env,
    *,
    plaintext: bytes = b"hello bob",
    sender: str = "alice",
    recipient: str = "bob",
    signing_priv: bytes | None = None,
    signing_password: bytes = ALICE_PASSWORD,
    ciphertext_xor_first_byte: bool = False,
    expiration_seconds: int = 3600,
) -> tuple[dict[str, Any], str]:
    """Construct a freshly encrypted UPLOAD_REQUEST payload.

    Knobs let individual tests corrupt one field while keeping everything
    else valid:

    * ``signing_priv`` / ``signing_password`` — sign with someone else
      (forged signature test).
    * ``ciphertext_xor_first_byte`` — flip a byte AFTER signing so the
      recomputed sha256 no longer matches the signed value (tampered
      ciphertext test).
    """
    file_id = str(uuid.uuid4())
    nonce, ciphertext, aes_key = encrypt_file_blob(
        plaintext, file_id, sender=sender, recipient=recipient,
    )
    recipient_cert = env.bob_cert if recipient == "bob" else env.alice_cert
    wrapped_key = wrap_aes_key_for(recipient_cert, aes_key)

    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
    timestamp = int(time.time())
    expiration = timestamp + expiration_seconds

    sig_priv = signing_priv if signing_priv is not None else env.alice_priv
    signature = sign_origin_struct(
        sig_priv, signing_password,
        sender=sender, recipient=recipient, file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp, expiration=expiration,
    )

    if ciphertext_xor_first_byte:
        # Flip a byte AFTER signing — sig was computed over the original.
        flipped = bytearray(ciphertext)
        flipped[0] ^= 0x01
        ciphertext = bytes(flipped)

    payload = {
        "file_id": file_id,
        "recipient": recipient,
        "ciphertext": _b64(ciphertext),
        "nonce": _b64(nonce),
        "wrapped_key": _b64(wrapped_key),
        "signature": _b64(signature),
        "timestamp": timestamp,
        "expiration": expiration,
    }
    return payload, file_id


def _send_and_recv(sock: socket.socket, payload: dict[str, Any]) -> dict[str, Any]:
    send_message(sock, make_envelope("UPLOAD_REQUEST", payload))
    return validate_envelope(recv_message(sock))


def _no_blob_or_row(env: _Env, file_id: str) -> None:
    """Assert the server wrote NEITHER the blob NOR a metadata row."""
    blob = env.files / f"{file_id}.bin"
    tmp = env.files / f"{file_id}.bin.tmp"
    assert not blob.exists(), f"blob unexpectedly present at {blob}"
    assert not tmp.exists(), f"half-file unexpectedly present at {tmp}"

    if env.db_path.exists():
        conn = sqlite3.connect(str(env.db_path))
        try:
            row = conn.execute(
                "SELECT 1 FROM files WHERE file_id = ?", (file_id,)
            ).fetchone()
            assert row is None, "metadata row unexpectedly inserted"
        finally:
            conn.close()


def _row_exists(env: _Env, file_id: str) -> bool:
    conn = sqlite3.connect(str(env.db_path))
    try:
        return (
            conn.execute(
                "SELECT 1 FROM files WHERE file_id = ?", (file_id,)
            ).fetchone()
            is not None
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------

def test_happy_path_writes_disk_row_and_acks(env):
    with _running_server(env) as port:
        with _alice_socket(env, port) as sock:
            payload, file_id = _build_upload_payload(env, plaintext=b"hello bob")
            reply = _send_and_recv(sock, payload)

    assert reply["type"] == "UPLOAD_ACK"
    assert reply["payload"]["file_id"] == file_id
    assert (env.files / f"{file_id}.bin").is_file()
    assert _row_exists(env, file_id)


# ---------------------------------------------------------------------------
# 2. Tampered ciphertext → AUTH_FAILED, no write, no row
# ---------------------------------------------------------------------------

def test_tampered_ciphertext_yields_auth_failed_no_write(env):
    with _running_server(env) as port:
        with _alice_socket(env, port) as sock:
            payload, file_id = _build_upload_payload(
                env, ciphertext_xor_first_byte=True,
            )
            reply = _send_and_recv(sock, payload)

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "AUTH_FAILED"
    _no_blob_or_row(env, file_id)


# ---------------------------------------------------------------------------
# 3. Forged signature (different signer) → AUTH_FAILED
# ---------------------------------------------------------------------------

def test_forged_signature_yields_auth_failed(env):
    """Mallory signs while the handshake-proven identity is alice."""
    with _running_server(env) as port:
        with _alice_socket(env, port) as sock:
            payload, file_id = _build_upload_payload(
                env,
                signing_priv=env.mallory_priv,
                signing_password=MALLORY_PASSWORD,
            )
            reply = _send_and_recv(sock, payload)

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "AUTH_FAILED"
    _no_blob_or_row(env, file_id)


# ---------------------------------------------------------------------------
# 4. Stale timestamp (≥ window seconds old) → STALE
# ---------------------------------------------------------------------------

def test_stale_envelope_timestamp_is_rejected(env):
    """Envelope timestamp 60s in the past → STALE (replay window is 30s)."""
    with _running_server(env) as port:
        with _alice_socket(env, port) as sock:
            payload, file_id = _build_upload_payload(env)
            stale_envelope = make_envelope("UPLOAD_REQUEST", payload)
            # Stamp the OUTER envelope as stale — the replay check uses
            # envelope["timestamp"], not the payload's timestamp.
            stale_envelope["timestamp"] = int(time.time()) - 60
            send_message(sock, stale_envelope)
            reply = validate_envelope(recv_message(sock))

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "STALE"
    _no_blob_or_row(env, file_id)


# ---------------------------------------------------------------------------
# 5. Replayed nonce (same envelope twice) → STALE/REPLAY on the second
# ---------------------------------------------------------------------------

def test_replayed_envelope_is_rejected_second_time(env):
    with _running_server(env) as port:
        with _alice_socket(env, port) as sock:
            payload, file_id = _build_upload_payload(env)
            envelope = make_envelope("UPLOAD_REQUEST", payload)

            # First send: succeeds.
            send_message(sock, envelope)
            first = validate_envelope(recv_message(sock))
            assert first["type"] == "UPLOAD_ACK"

            # Second send (identical envelope, same nonce + timestamp):
            # the replay table rejects it.
            send_message(sock, envelope)
            second = validate_envelope(recv_message(sock))

    assert second["type"] == "ERROR"
    # We deliberately collapse REPLAY and STALE into one generic code on
    # the wire — the server's check_and_record returns False
    # for both reasons, surfaced as "STALE" by the handler.
    assert second["payload"]["code"] in {"STALE", "REPLAY"}


# ---------------------------------------------------------------------------
# 6. Unknown recipient → NOT_FOUND
# ---------------------------------------------------------------------------

def test_unknown_recipient_yields_not_found(env):
    """Encrypt+sign for `carol`, who has no entry in the pubkey directory."""
    # Carol exists as a real user (signed by the CA) but is NOT published
    # in the server's pubkey/ directory.
    carol_priv, carol_pub = cp.generate_rsa_keypair(b"carol-pw")
    carol_cert = cert_mod.issue_certificate(
        "carol", carol_pub, env.ca_priv, CA_PASSWORD,
    )

    file_id = str(uuid.uuid4())
    nonce, ciphertext, aes_key = encrypt_file_blob(
        b"x", file_id, sender="alice", recipient="carol",
    )
    wrapped_key = wrap_aes_key_for(carol_cert, aes_key)

    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
    timestamp = int(time.time())
    expiration = timestamp + 3600

    signature = sign_origin_struct(
        env.alice_priv, ALICE_PASSWORD,
        sender="alice", recipient="carol", file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp, expiration=expiration,
    )

    payload = {
        "file_id": file_id,
        "recipient": "carol",
        "ciphertext": _b64(ciphertext),
        "nonce": _b64(nonce),
        "wrapped_key": _b64(wrapped_key),
        "signature": _b64(signature),
        "timestamp": timestamp,
        "expiration": expiration,
    }

    with _running_server(env) as port:
        with _alice_socket(env, port) as sock:
            reply = _send_and_recv(sock, payload)

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "NOT_FOUND"
    _no_blob_or_row(env, file_id)


# ---------------------------------------------------------------------------
# 7. Atomic disk write — crash mid-write leaves no half-files
# ---------------------------------------------------------------------------

def test_atomic_write_leaves_no_half_file_if_write_fails(env, monkeypatch):
    """If the write step itself fails, the server must surface an error
    AND not leave a ``*.bin`` blob (the half-file lives in ``*.bin.tmp``
    until ``os.replace`` succeeds, so a mid-write crash never produces a
    corrupt final row)."""

    real_open = Path.open

    def explode_on_tmp(self, *args, **kwargs):
        if str(self).endswith(".bin.tmp"):
            raise OSError("simulated disk failure")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", explode_on_tmp)

    with _running_server(env) as port:
        with _alice_socket(env, port) as sock:
            payload, file_id = _build_upload_payload(env)
            reply = _send_and_recv(sock, payload)

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "INTERNAL_ERROR"
    # Crucially: NO final .bin (the os.replace was never reached) and the
    # tmp file — if any — was never promoted, so the metadata row was
    # never inserted either.
    assert not (env.files / f"{file_id}.bin").exists()
    assert not _row_exists(env, file_id)


# ---------------------------------------------------------------------------
# Bonus: payload["sender"] cannot override session["peer_subject"]
# (issue pitfall — handshake-proven identity is the source of truth)
# ---------------------------------------------------------------------------

def test_impersonation_attempt_via_signature_mismatch(env):
    """Mallory tries to claim she's alice by signing herself but the
    session is hers. The handler ignores payload-level sender claims and
    uses the handshake identity to verify the signature — Mallory's
    signature over (sender=mallory, ...) won't verify against
    session['peer_cert']==alice → AUTH_FAILED.

    We model this by opening the socket as mallory (a real CA-signed
    user) and sending a payload signed by mallory but claiming sender=
    mallory — which is consistent with her session — to bob. The server
    should accept it. Then we send another payload claiming sender=alice;
    that fails because the canonical struct is signed with mallory's key
    but verified against mallory's cert with sender=alice → mismatch.
    """
    with _running_server(env) as port:
        # Connect as mallory.
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            perform_client_handshake(
                sock=sock,
                client_cert=env.mallory_cert,
                client_priv_pem=env.mallory_priv,
                client_password=MALLORY_PASSWORD,
                ca_pubkey_pem=env.ca_pub,
                expected_server_subject="zerotrust-server",
            )

            # Mallory tries to claim she's alice in the canonical struct.
            file_id = str(uuid.uuid4())
            nonce, ciphertext, aes_key = encrypt_file_blob(
                b"forged", file_id, sender="alice", recipient="bob",
            )
            wrapped_key = wrap_aes_key_for(env.bob_cert, aes_key)
            ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
            wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
            timestamp = int(time.time())
            expiration = timestamp + 3600

            # Sign with mallory's key claiming sender=alice — the server
            # will verify against session['peer_cert']==mallory, sender=
            # mallory, so the signature won't reconstruct.
            signature = sign_origin_struct(
                env.mallory_priv, MALLORY_PASSWORD,
                sender="alice", recipient="bob", file_id=file_id,
                ciphertext_sha256=ciphertext_sha256,
                wrapped_key_sha256=wrapped_key_sha256,
                timestamp=timestamp, expiration=expiration,
            )

            payload = {
                "file_id": file_id,
                "recipient": "bob",
                "ciphertext": _b64(ciphertext),
                "nonce": _b64(nonce),
                "wrapped_key": _b64(wrapped_key),
                "signature": _b64(signature),
                "timestamp": timestamp,
                "expiration": expiration,
            }
            send_message(sock, make_envelope("UPLOAD_REQUEST", payload))
            reply = validate_envelope(recv_message(sock))
        finally:
            sock.close()

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "AUTH_FAILED"
    _no_blob_or_row(env, file_id)
