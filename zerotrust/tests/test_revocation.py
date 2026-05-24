"""Server-side REVOKE_REQUEST regression suite (issue #24 / bonus).

Each bullet from the issue's acceptance-criteria + required-tests
sections gets its own test, plus a few defence-in-depth tests for the
pitfalls (payload-sender override attempt, blob-must-stay-on-disk).

We drive the server through a real ``ThreadingTCPServer`` thread and
hand-build envelopes for the negative cases so each test can corrupt
exactly one thing.  The happy path goes through the real
:func:`zerotrust.client.revoke.revoke_file` helper so the helper itself
gets covered by integration.
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
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.handshake import perform_client_handshake
from zerotrust.client.revoke import revoke_file
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
from zerotrust.common.revoke import sign_revoke_struct
from zerotrust.server.main import ZeroTrustRequestHandler, ZeroTrustServer

CA_PASSWORD = b"ca-revoke-pw"
SERVER_PASSWORD = b"server-revoke-pw"
ALICE_PASSWORD = b"alice-revoke-pw"
BOB_PASSWORD = b"bob-revoke-pw"
MALLORY_PASSWORD = b"mallory-revoke-pw"


# ---------------------------------------------------------------------------
# Fixture environment — three CA-signed users (alice sender, bob recipient,
# mallory attacker) + server + DB on disk.
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
def _session_socket(
    env: _Env,
    port: int,
    *,
    user: str = "alice",
) -> Iterator[dict[str, Any]]:
    """Open a TCP socket, run the handshake as *user*, yield a session dict
    compatible with the client helpers (so we can call
    :func:`revoke_file` against the real server)."""
    creds = {
        "alice": (env.alice_cert, env.alice_priv, ALICE_PASSWORD),
        "bob": (env.bob_cert, env.bob_priv, BOB_PASSWORD),
        "mallory": (env.mallory_cert, env.mallory_priv, MALLORY_PASSWORD),
    }
    client_cert, client_priv, client_pw = creds[user]

    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        state = perform_client_handshake(
            sock=sock,
            client_cert=client_cert,
            client_priv_pem=client_priv,
            client_password=client_pw,
            ca_pubkey_pem=env.ca_pub,
            expected_server_subject="zerotrust-server",
        )
        live = dict(state)
        live.update({
            "sock": sock,
            "username": user,
            "client_cert": client_cert,
            "client_priv_pem": client_priv,
            "client_password": client_pw,
            "ca_pubkey_pem": env.ca_pub,
        })
        yield live
    finally:
        sock.close()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _upload_one(
    env: _Env,
    port: int,
    *,
    sender_user: str = "alice",
    recipient: str = "bob",
    plaintext: bytes = b"hello bob",
) -> str:
    """Push one valid upload through the live server and return file_id."""
    creds = {
        "alice": (env.alice_priv, ALICE_PASSWORD, env.alice_cert),
    }
    sender_priv, sender_pw, _sender_cert = creds[sender_user]
    recipient_cert = env.bob_cert if recipient == "bob" else env.alice_cert

    file_id = str(uuid.uuid4())
    nonce, ciphertext, aes_key = encrypt_file_blob(
        plaintext, file_id, sender=sender_user, recipient=recipient,
    )
    wrapped_key = wrap_aes_key_for(recipient_cert, aes_key)
    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
    ts = int(time.time())
    expiration = ts + 3600
    signature = sign_origin_struct(
        sender_priv, sender_pw,
        sender=sender_user, recipient=recipient, file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=ts, expiration=expiration,
    )
    payload = {
        "file_id": file_id,
        "recipient": recipient,
        "ciphertext": _b64(ciphertext),
        "nonce": _b64(nonce),
        "wrapped_key": _b64(wrapped_key),
        "signature": _b64(signature),
        "timestamp": ts,
        "expiration": expiration,
    }
    with _session_socket(env, port, user=sender_user) as session:
        send_message(session["sock"], make_envelope("UPLOAD_REQUEST", payload))
        reply = validate_envelope(recv_message(session["sock"]))
    assert reply["type"] == "UPLOAD_ACK", reply
    return file_id


def _row_status(env: _Env, file_id: str) -> str | None:
    conn = sqlite3.connect(str(env.db_path))
    try:
        row = conn.execute(
            "SELECT status FROM files WHERE file_id = ?", (file_id,)
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


def _force_status(env: _Env, file_id: str, status: str) -> None:
    """Bypass the wire to plant a pre-existing state for state-machine tests."""
    conn = sqlite3.connect(str(env.db_path))
    try:
        with conn:
            conn.execute(
                "UPDATE files SET status = ? WHERE file_id = ?",
                (status, file_id),
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. Acceptance: Alice revokes her own pending upload → status flips to 'revoked'.
# ---------------------------------------------------------------------------

def test_happy_revoke_flips_status_to_revoked(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        assert _row_status(env, file_id) == "pending"

        with _session_socket(env, port, user="alice") as session:
            ack = revoke_file(session, file_id)

    assert ack["file_id"] == file_id
    assert ack["status"] == "revoked"
    assert _row_status(env, file_id) == "revoked"
    # Per issue pitfall: blob must NOT be deleted by revoke.
    assert (env.files / f"{file_id}.bin").is_file()


# ---------------------------------------------------------------------------
# 2. Acceptance: Bob tries to download afterwards → REVOKED error, no blob shipped.
# ---------------------------------------------------------------------------

def test_revoked_download_returns_revoked_with_no_blob_bytes(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)

        # Alice revokes.
        with _session_socket(env, port, user="alice") as session:
            revoke_file(session, file_id)

        # Bob tries to download.  Expect an ERROR/REVOKED envelope and
        # absolutely no DOWNLOAD_RESPONSE / ciphertext on the wire.
        with _session_socket(env, port, user="bob") as session:
            send_message(
                session["sock"],
                make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}),
            )
            reply = validate_envelope(recv_message(session["sock"]))

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "REVOKED"
    # No download payload smuggled in.
    assert "ciphertext" not in reply["payload"]
    assert "wrapped_key" not in reply["payload"]


# ---------------------------------------------------------------------------
# 3. Acceptance: Mallory tries to revoke Alice's file → NOT_AUTHORIZED.
# ---------------------------------------------------------------------------

def test_non_owner_revoke_is_not_authorized_and_row_unchanged(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        assert _row_status(env, file_id) == "pending"

        with _session_socket(env, port, user="mallory") as session:
            with pytest.raises(ProtocolError) as exc_info:
                revoke_file(session, file_id)

    assert str(exc_info.value) == "NOT_AUTHORIZED"
    assert _row_status(env, file_id) == "pending"


# ---------------------------------------------------------------------------
# 4. Acceptance: Alice tries to revoke after Bob downloaded → ALREADY_DOWNLOADED.
#    We simulate the post-download state by directly flipping the row, which is
#    simpler than driving the full DOWNLOAD_ACK round-trip and exercises the
#    state-machine branch the issue explicitly calls out.
# ---------------------------------------------------------------------------

def test_revoke_after_download_returns_already_downloaded(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        _force_status(env, file_id, "downloaded")

        with _session_socket(env, port, user="alice") as session:
            with pytest.raises(ProtocolError) as exc_info:
                revoke_file(session, file_id)

    assert str(exc_info.value) == "ALREADY_DOWNLOADED"
    assert _row_status(env, file_id) == "downloaded"


# ---------------------------------------------------------------------------
# 5. Acceptance: Alice revokes the same file twice → second call returns
#    success (idempotent), no extra audit-INFO line.
# ---------------------------------------------------------------------------

def test_double_revoke_is_idempotent_success(env, caplog):
    import logging
    with _running_server(env) as port:
        file_id = _upload_one(env, port)

        with caplog.at_level(logging.INFO, logger="zerotrust"):
            with _session_socket(env, port, user="alice") as session:
                first = revoke_file(session, file_id)
            # Second revoke — same file, same user.
            with _session_socket(env, port, user="alice") as session:
                second = revoke_file(session, file_id)

    assert first["status"] == "revoked"
    assert second["status"] == "revoked"
    assert _row_status(env, file_id) == "revoked"

    # "No log noise" acceptance bullet: exactly one INFO event=revoke_accept
    # line — the second call must not emit another.
    accept_lines = [
        r for r in caplog.records
        if r.levelno == logging.INFO and "event=revoke_accept" in r.message
    ]
    assert len(accept_lines) == 1, (
        f"expected exactly one revoke_accept INFO, got {len(accept_lines)}:\n"
        f"{caplog.text}"
    )


# ---------------------------------------------------------------------------
# 6. Acceptance: Revoke without a valid signature → AUTH_FAILED.
#    We hand-build the envelope with a garbage signature so the canonical
#    struct will not reconstruct.
# ---------------------------------------------------------------------------

def test_revoke_with_garbage_signature_is_auth_failed(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)

        with _session_socket(env, port, user="alice") as session:
            payload = {
                "file_id": file_id,
                "timestamp": int(time.time()),
                "signature": _b64(b"\x00" * 256),  # garbage, wrong length even
            }
            send_message(
                session["sock"], make_envelope("REVOKE_REQUEST", payload),
            )
            reply = validate_envelope(recv_message(session["sock"]))

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "AUTH_FAILED"
    assert _row_status(env, file_id) == "pending"


# ---------------------------------------------------------------------------
# 7. Required test: forged signature (sign with a different key, present
#    Alice's session cert) → AUTH_FAILED.  Mallory's key signs but the
#    session cert is Alice's, so the verify against Alice's pubkey fails.
# ---------------------------------------------------------------------------

def test_revoke_forged_signature_yields_auth_failed(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)

        with _session_socket(env, port, user="alice") as session:
            ts = int(time.time())
            # Sign claiming sender=alice but with mallory's private key —
            # verify_revoke_struct will reconstruct against alice's pubkey
            # (the session cert), which won't match.
            forged = sign_revoke_struct(
                env.mallory_priv, MALLORY_PASSWORD,
                sender="alice", file_id=file_id, timestamp=ts,
            )
            payload = {
                "file_id": file_id,
                "timestamp": ts,
                "signature": _b64(forged),
            }
            send_message(
                session["sock"], make_envelope("REVOKE_REQUEST", payload),
            )
            reply = validate_envelope(recv_message(session["sock"]))

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "AUTH_FAILED"
    assert _row_status(env, file_id) == "pending"


# ---------------------------------------------------------------------------
# 8. Required test: replay revoke envelope → STALE on the second send.
# ---------------------------------------------------------------------------

def test_replay_revoke_envelope_is_rejected(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)

        with _session_socket(env, port, user="alice") as session:
            ts = int(time.time())
            sig = sign_revoke_struct(
                env.alice_priv, ALICE_PASSWORD,
                sender="alice", file_id=file_id, timestamp=ts,
            )
            payload = {
                "file_id": file_id,
                "timestamp": ts,
                "signature": _b64(sig),
            }
            envelope = make_envelope("REVOKE_REQUEST", payload)

            send_message(session["sock"], envelope)
            first = validate_envelope(recv_message(session["sock"]))
            assert first["type"] == "REVOKE_ACK"

            # Same envelope again → STALE/REPLAY.
            send_message(session["sock"], envelope)
            second = validate_envelope(recv_message(session["sock"]))

    assert second["type"] == "ERROR"
    assert second["payload"]["code"] in {"STALE", "REPLAY"}
    # Status doesn't regress.
    assert _row_status(env, file_id) == "revoked"


# ---------------------------------------------------------------------------
# 9. Pitfall: payload['sender'] cannot override session['peer_subject'].
#    Mallory connects (so the handshake-proven identity is mallory) and
#    tries to revoke Alice's file by signing a struct that claims
#    sender=alice.  The server rebuilds the canonical struct from the
#    *session* identity, so the signature won't reconstruct, AND the
#    ownership check would refuse anyway.  Either failure mode is
#    acceptable; both result in the row staying pending.
# ---------------------------------------------------------------------------

def test_payload_sender_field_cannot_impersonate(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)

        with _session_socket(env, port, user="mallory") as session:
            ts = int(time.time())
            # Sign a struct claiming sender=alice — mallory's session
            # would re-derive canonical(sender=mallory, ...) so this
            # signature won't verify even if we got past ownership.
            sig = sign_revoke_struct(
                env.mallory_priv, MALLORY_PASSWORD,
                sender="alice", file_id=file_id, timestamp=ts,
            )
            payload = {
                "file_id": file_id,
                "timestamp": ts,
                "signature": _b64(sig),
            }
            send_message(
                session["sock"], make_envelope("REVOKE_REQUEST", payload),
            )
            reply = validate_envelope(recv_message(session["sock"]))

    assert reply["type"] == "ERROR"
    # Ownership check fires before signature verify, so the wire code is
    # NOT_AUTHORIZED.  That's the desired outcome — it proves we never
    # honoured a payload-side sender claim.
    assert reply["payload"]["code"] == "NOT_AUTHORIZED"
    assert _row_status(env, file_id) == "pending"


# ---------------------------------------------------------------------------
# 10. Pitfall: revoke must not delete the ciphertext blob.
#     The cleanup thread (issue #27) is the only thing allowed to touch
#     the filesystem; revoke just flips the status.
# ---------------------------------------------------------------------------

def test_revoke_does_not_delete_blob(env):
    with _running_server(env) as port:
        file_id = _upload_one(env, port)
        blob_path = env.files / f"{file_id}.bin"
        assert blob_path.is_file()

        with _session_socket(env, port, user="alice") as session:
            revoke_file(session, file_id)

    # Blob must still be there after revoke.
    assert blob_path.is_file()
    assert _row_status(env, file_id) == "revoked"


# ---------------------------------------------------------------------------
# 11. NOT_FOUND: revoking a file_id the server has never seen.
# ---------------------------------------------------------------------------

def test_revoke_unknown_file_id_yields_not_found(env):
    with _running_server(env) as port:
        with _session_socket(env, port, user="alice") as session:
            with pytest.raises(ProtocolError) as exc_info:
                revoke_file(session, str(uuid.uuid4()))

    assert str(exc_info.value) == "NOT_FOUND"
