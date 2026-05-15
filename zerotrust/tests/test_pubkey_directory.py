"""Tests for #21 — GET_PUBKEY / PUBKEY_RESPONSE roundtrip + defences."""

from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.peer import fetch_peer_cert
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import AuthError
from zerotrust.common.protocol import make_envelope, recv_message, send_message
from zerotrust.server.handler import serve_connection
from zerotrust.server.storage_layout import (
    USERNAME_REGEX,
    pubkey_path_for,
)


PASSWORD = b"pubkey-test-password"


@pytest.fixture
def ca_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture
def storage_base(tmp_path: Path, ca_keys) -> str:
    """A populated storage directory: pubkeys/alice.json and bob.json."""
    ca_priv, _ = ca_keys
    pubkeys_dir = tmp_path / "pubkeys"
    pubkeys_dir.mkdir()
    for username in ("alice", "bob"):
        _, user_pub = cp.generate_rsa_keypair(PASSWORD)
        cert = cert_mod.issue_certificate(username, user_pub, ca_priv, PASSWORD)
        (pubkeys_dir / f"{username}.json").write_text(
            json.dumps(cert, sort_keys=True), encoding="utf-8"
        )
    return str(tmp_path)


def _run_server(server_state: dict) -> tuple[int, threading.Thread]:
    """Spin up a one-shot server thread on an ephemeral port."""
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.bind(("127.0.0.1", 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    def run() -> None:
        try:
            conn, addr = listen.accept()
            try:
                serve_connection(conn, addr, server_state)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        finally:
            listen.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t


# ---------------------------------------------------------------------------
# Username regex — the path traversal boundary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("good", ["alice", "bob_42", "user-1", "A", "z" * 32])
def test_regex_accepts_safe_usernames(good):
    assert USERNAME_REGEX.match(good) is not None


@pytest.mark.parametrize("bad", [
    "../etc/passwd",
    "..",
    ".",
    "a/b",
    "a\\b",
    "",
    "z" * 33,           # too long
    "alice\x00",        # null byte
    "alice.json",       # dot would let attacker craft paths
    "  alice",          # whitespace
])
def test_regex_rejects_unsafe_usernames(bad):
    assert USERNAME_REGEX.match(bad) is None


# ---------------------------------------------------------------------------
# pubkey_path_for
# ---------------------------------------------------------------------------

def test_pubkey_path_for_layout():
    assert pubkey_path_for("server/storage", "alice").endswith(
        os.path.join("pubkeys", "alice.json")
    )


# ---------------------------------------------------------------------------
# End-to-end: fetch_peer_cert + serve_connection
# ---------------------------------------------------------------------------

def test_fetch_peer_cert_happy_path(ca_keys, storage_base):
    _, ca_pub = ca_keys
    port, t = _run_server({
        "storage_base": storage_base,
        "ca_pubkey_pem": ca_pub,
    })
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    try:
        cert = fetch_peer_cert(sock, ca_pub, "alice")
    finally:
        sock.close()
        t.join(timeout=2.0)

    assert cert["subject"] == "alice"
    # Returned cert verifies independently against the client's CA.
    assert cert_mod.verify_certificate(cert, ca_pub) is True


def test_fetch_unknown_user_raises_auth_error(ca_keys, storage_base):
    _, ca_pub = ca_keys
    port, t = _run_server({
        "storage_base": storage_base,
        "ca_pubkey_pem": ca_pub,
    })
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    try:
        with pytest.raises(AuthError):
            fetch_peer_cert(sock, ca_pub, "nonexistent")
    finally:
        sock.close()
        t.join(timeout=2.0)


@pytest.mark.parametrize("evil", [
    "../../../etc/passwd",
    "..",
    "a/b",
    "alice\x00",
    "alice.json",
])
def test_path_traversal_rejected_at_protocol_layer(ca_keys, storage_base, evil):
    """An attacker who bypasses the client-side regex (e.g. by sending
    a hand-crafted envelope) still hits the server's regex boundary."""
    _, ca_pub = ca_keys
    port, t = _run_server({
        "storage_base": storage_base,
        "ca_pubkey_pem": ca_pub,
    })
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    try:
        # Hand-craft the request — bypass fetch_peer_cert's regex.
        send_message(sock, make_envelope("GET_PUBKEY", {"username": evil}))
        reply = recv_message(sock)
        assert reply["type"] == "ERROR"
        assert reply["payload"]["code"] == "NOT_FOUND"
    finally:
        sock.close()
        t.join(timeout=2.0)


def test_planted_cert_fails_ca_verification(ca_keys, storage_base, tmp_path):
    """Defence-in-depth: if an attacker writes a 'cert' file directly to
    the pubkeys directory, the server's own CA re-verification rejects
    it — the client never sees a forged peer cert."""
    _, ca_pub = ca_keys
    # Plant a self-issued cert (wrong CA) for username 'mallory'.
    other_ca_priv, _ = cp.generate_rsa_keypair(PASSWORD)
    _, m_pub = cp.generate_rsa_keypair(PASSWORD)
    planted = cert_mod.issue_certificate(
        "mallory", m_pub, other_ca_priv, PASSWORD
    )
    (Path(storage_base) / "pubkeys" / "mallory.json").write_text(
        json.dumps(planted, sort_keys=True), encoding="utf-8"
    )

    port, t = _run_server({
        "storage_base": storage_base,
        "ca_pubkey_pem": ca_pub,
    })
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    try:
        with pytest.raises(AuthError):
            fetch_peer_cert(sock, ca_pub, "mallory")
    finally:
        sock.close()
        t.join(timeout=2.0)


def test_subject_swap_attempt_rejected_by_client(ca_keys, storage_base, tmp_path):
    """A misconfigured (or hostile) server stores Alice's cert in Bob's
    slot. The client's ``expected_subject`` check catches this — the
    cert verifies against the CA but the subject is wrong."""
    _, ca_pub = ca_keys
    alice_cert = json.loads(
        (Path(storage_base) / "pubkeys" / "alice.json").read_text()
    )
    # Save Alice's cert under Bob's filename. (Server defence catches
    # this too because verify_certificate is called with
    # expected_subject=username, but we exercise the client end here.)
    (Path(storage_base) / "pubkeys" / "carol.json").write_text(
        json.dumps(alice_cert, sort_keys=True), encoding="utf-8"
    )
    port, t = _run_server({
        "storage_base": storage_base,
        "ca_pubkey_pem": ca_pub,
    })
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    try:
        with pytest.raises(AuthError):
            fetch_peer_cert(sock, ca_pub, "carol")
    finally:
        sock.close()
        t.join(timeout=2.0)


def test_missing_ca_trust_anchor_serves_not_found(ca_keys, storage_base):
    """If the server's own state is broken (no ca_pubkey_pem), serve
    NOT_FOUND rather than crashing or leaking the real issue."""
    _, ca_pub = ca_keys
    port, t = _run_server({
        "storage_base": storage_base,
        # Note: ca_pubkey_pem missing on purpose.
    })
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    try:
        with pytest.raises(AuthError):
            fetch_peer_cert(sock, ca_pub, "alice")
    finally:
        sock.close()
        t.join(timeout=2.0)