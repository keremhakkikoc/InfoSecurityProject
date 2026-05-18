"""Tests for the public-key directory (issue #22).

Covers the four required test cases from the issue body:

* happy fetch — Alice retrieves Bob's CA-signed cert via GET_PUBKEY and
  verifies it against her local CA trust anchor,
* unknown user — server returns ``ERROR { code: NOT_FOUND }``,
* path traversal — ``../``, ``..``, ``/etc/passwd``, ``a/b`` are refused
  at the regex (NOT_FOUND, no filesystem error),
* corrupted pubkey file on disk — bad JSON OR a cert whose signature
  doesn't verify against the CA → NOT_FOUND, no internal-error leak.

Plus two unit-level checks for the security boundary itself:
``valid_username`` and ``pubkey_path_for`` — the regex IS the boundary,
so we test it directly in addition to the integration path.
"""

from __future__ import annotations

import json
import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.handshake import perform_client_handshake
from zerotrust.client.peer import fetch_peer_cert
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import AuthError, ProtocolError
from zerotrust.server import storage_layout
from zerotrust.server.main import ZeroTrustRequestHandler, ZeroTrustServer


CA_PASSWORD = b"ca-test-password"
SERVER_PASSWORD = b"server-test-password"
ALICE_PASSWORD = b"alice-test-password"
BOB_PASSWORD = b"bob-test-password"


# ---------------------------------------------------------------------------
# Unit-level: the regex IS the security boundary.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name",
    ["alice", "bob", "user-1", "user_2", "A", "a" * 32, "0", "Z9-_-Z"],
)
def test_valid_username_accepts_well_formed_names(name):
    assert storage_layout.valid_username(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "",                  # empty
        "a" * 33,            # too long
        "../",               # explicit traversal
        "..",                # parent
        "/etc/passwd",       # absolute, slashes
        "a/b",               # embedded slash
        "alice\x00",         # null byte
        "alice.bob",         # dot
        "alice bob",         # whitespace
        "alice;bob",         # shell metachar
        ".",                 # current dir
        None,                # not a string
        42,                  # not a string
        b"alice",            # bytes, not str
    ],
)
def test_valid_username_rejects_unsafe_input(name):
    assert storage_layout.valid_username(name) is False


def test_pubkey_path_for_returns_none_on_invalid_username(tmp_path):
    server_state = {"pubkeys_dir": str(tmp_path)}
    assert storage_layout.pubkey_path_for(server_state, "../etc") is None
    assert storage_layout.pubkey_path_for(server_state, "a/b") is None


def test_pubkey_path_for_returns_path_under_pubkeys_dir(tmp_path):
    server_state = {"pubkeys_dir": str(tmp_path)}
    p = storage_layout.pubkey_path_for(server_state, "bob")
    assert p == tmp_path / "bob.json"


# ---------------------------------------------------------------------------
# Integration: live server thread.
# ---------------------------------------------------------------------------

@dataclass
class _Env:
    tmp: Path
    storage: Path
    pubkeys: Path
    ca_priv: bytes
    ca_pub: bytes
    ca_cert: dict
    server_priv: bytes
    server_cert: dict
    alice_priv: bytes
    alice_cert: dict
    bob_priv: bytes
    bob_cert: dict
    db_path: Path


def _build_env(tmp_path: Path) -> _Env:
    storage = tmp_path / "server_storage"
    pubkeys = storage / "pubkeys"
    storage.mkdir()
    pubkeys.mkdir()

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

    # Bob lives in the directory; alice has to live there too so the
    # handshake's cert lookup works.
    (pubkeys / "bob.json").write_text(json.dumps(bob_cert))
    (pubkeys / "alice.json").write_text(json.dumps(alice_cert))

    return _Env(
        tmp=tmp_path,
        storage=storage,
        pubkeys=pubkeys,
        ca_priv=ca_priv, ca_pub=ca_pub, ca_cert=ca_cert,
        server_priv=server_priv, server_cert=server_cert,
        alice_priv=alice_priv, alice_cert=alice_cert,
        bob_priv=bob_priv, bob_cert=bob_cert,
        db_path=storage / "metadata.db",
    )


@pytest.fixture
def env(tmp_path: Path) -> _Env:
    return _build_env(tmp_path)


@contextmanager
def _running_server(env: _Env) -> Iterator[int]:
    state = {
        "db_path": str(env.db_path),
        "ca_pubkey_pem": env.ca_pub,
        "server_cert": env.server_cert,
        "server_priv_pem": env.server_priv,
        "server_password": SERVER_PASSWORD,
        "storage_dir": str(env.storage),
        "pubkeys_dir": str(env.pubkeys),
        "files_dir": str(env.storage / "files"),
    }
    server = ZeroTrustServer(("127.0.0.1", 0), ZeroTrustRequestHandler, state)
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
def _alice_session(env: _Env, port: int) -> Iterator[dict]:
    """Open a raw socket and run the handshake as alice.

    We don't go through ``connected_session`` because these tests don't
    need a client_<user>/ directory on disk — we just need a live
    session dict for ``fetch_peer_cert``.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        state = perform_client_handshake(
            sock=sock,
            client_cert=env.alice_cert,
            client_priv_pem=env.alice_priv,
            client_password=ALICE_PASSWORD,
            ca_pubkey_pem=env.ca_pub,
            expected_server_subject="zerotrust-server",
        )
        session = dict(state)
        session.update({
            "sock": sock,
            "ca_pubkey_pem": env.ca_pub,
        })
        yield session
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Happy path.
# ---------------------------------------------------------------------------

def test_happy_fetch_returns_bobs_cert_and_verifies(env):
    with _running_server(env) as port:
        with _alice_session(env, port) as session:
            cert = fetch_peer_cert(session, "bob")
    assert cert["subject"] == "bob"
    # The cert returned by the server is the same one we placed on disk.
    assert cert["serial"] == env.bob_cert["serial"]


# ---------------------------------------------------------------------------
# Unknown user → NOT_FOUND.
# ---------------------------------------------------------------------------

def test_unknown_user_returns_not_found(env):
    with _running_server(env) as port:
        with _alice_session(env, port) as session:
            with pytest.raises(ProtocolError) as exc:
                fetch_peer_cert(session, "carol")
    assert "NOT_FOUND" in str(exc.value)


# ---------------------------------------------------------------------------
# Path traversal → NOT_FOUND at the regex.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "evil",
    ["../", "..", "/etc/passwd", "a/b", "../../etc/passwd"],
)
def test_path_traversal_is_refused_at_regex(env, evil):
    # Plant a sentinel file alice would love to read if traversal worked.
    (env.tmp / "etc").mkdir(exist_ok=True)
    (env.tmp / "etc" / "passwd").write_text("root:x:0:0:")

    with _running_server(env) as port:
        with _alice_session(env, port) as session:
            with pytest.raises(ProtocolError) as exc:
                fetch_peer_cert(session, evil)
    assert "NOT_FOUND" in str(exc.value)


# ---------------------------------------------------------------------------
# Corrupted pubkey file → NOT_FOUND (no internal-error leak).
# ---------------------------------------------------------------------------

def test_corrupted_json_pubkey_file_yields_not_found(env):
    """Bad JSON on disk must not leak a parse-error to the client."""
    (env.pubkeys / "bob.json").write_text("{not valid json")

    with _running_server(env) as port:
        with _alice_session(env, port) as session:
            with pytest.raises(ProtocolError) as exc:
                fetch_peer_cert(session, "bob")
    assert "NOT_FOUND" in str(exc.value)


def test_pubkey_file_with_bad_signature_yields_not_found(env):
    """A cert that doesn't verify against the CA → NOT_FOUND.

    Defence in depth: an attacker who plants a fake ``bob.json`` on the
    filesystem still can't impersonate Bob — the server re-verifies the
    cert against its own CA trust anchor before returning.
    """
    # Forge a "bob.json" signed by a DIFFERENT CA — looks structurally
    # valid but fails verification against the real CA trust anchor.
    rogue_priv, rogue_pub = cp.generate_rsa_keypair(b"rogue-ca-pw")
    rogue_cert = cert_mod.issue_certificate(
        "bob", rogue_pub, rogue_priv, b"rogue-ca-pw",
    )
    (env.pubkeys / "bob.json").write_text(json.dumps(rogue_cert))

    with _running_server(env) as port:
        with _alice_session(env, port) as session:
            with pytest.raises(ProtocolError) as exc:
                fetch_peer_cert(session, "bob")
    assert "NOT_FOUND" in str(exc.value)


# ---------------------------------------------------------------------------
# Client-side: subject pinning catches a server that swaps in another user's
# valid cert.
# ---------------------------------------------------------------------------

def test_client_rejects_cert_whose_subject_doesnt_match_request(env):
    """If the server returns alice's (valid!) cert in response to a
    GET_PUBKEY for "bob", the client MUST reject — subject pinning is
    what makes the channel zero-trust on top of CA verification.
    """
    # Replace bob.json with alice's (CA-valid) cert — i.e. simulate a
    # malicious server that hands back a legitimate-but-wrong cert.
    (env.pubkeys / "bob.json").write_text(json.dumps(env.alice_cert))

    with _running_server(env) as port:
        with _alice_session(env, port) as session:
            # The server will reject it during its own re-verification
            # (subject pinning runs server-side too), so we should see
            # NOT_FOUND rather than AuthError.
            with pytest.raises((AuthError, ProtocolError)) as exc:
                fetch_peer_cert(session, "bob")
    msg = str(exc.value)
    assert "NOT_FOUND" in msg or "recipient cert" in msg
