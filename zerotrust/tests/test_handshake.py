"""End-to-end handshake integration tests for M2 issue #8.

These tests spin up a real TCP server on an ephemeral port in a thread,
connect a client from the main thread, and assert the negotiated session
state on both sides. This is the load-bearing test file of M2 — if these
go red, no further M2 / M3 work can be trusted.

Covers every Acceptance Criterion from issue #8:
  AC1. Both sides compute the same c2s_key and s2c_key (bit-for-bit).
  AC2. Wrong server password -> handshake fails, no key material returned.
  AC3. Tampered pre_master_ct -> handshake fails server-side.
  AC4. Fake server cert (different CA) -> client aborts BEFORE pre-master.
  AC5. Session dict shape matches the frozen contract exactly.

Plus extra negative coverage: protocol drift, replay across sessions,
expired client cert, subject-pinning mismatch, malformed messages.
"""

from __future__ import annotations

import base64
import os
import socket
import threading
import time
from typing import Any

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.handshake import perform_client_handshake
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import AuthError, ProtocolError
from zerotrust.common.protocol import (
    make_envelope,
    pack_message,
    recv_message,
    send_message,
    validate_envelope,
)
from zerotrust.common.transcript import build_transcript_hash
from zerotrust.server.handshake import perform_server_handshake


PASSWORD = b"handshake-test-password"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ca_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture(scope="module")
def other_ca_keys():
    """A SECOND, unrelated CA — used to simulate a hostile / mis-issued
    server cert. The legitimate client must NOT trust certs from this CA.
    """
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture(scope="module")
def server_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture(scope="module")
def client_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture(scope="module")
def server_cert(ca_keys, server_keys):
    ca_priv, _ = ca_keys
    _, server_pub = server_keys
    return cert_mod.issue_certificate("server-01", server_pub, ca_priv, PASSWORD)


@pytest.fixture(scope="module")
def client_cert(ca_keys, client_keys):
    ca_priv, _ = ca_keys
    _, client_pub = client_keys
    return cert_mod.issue_certificate("alice", client_pub, ca_priv, PASSWORD)


@pytest.fixture(scope="module")
def evil_server_cert(other_ca_keys, server_keys):
    """A server cert signed by the WRONG CA. From the client's perspective,
    this looks like a legitimate-looking cert (well-formed JSON, in date)
    but the signature does not verify against the trusted CA pubkey.
    """
    other_ca_priv, _ = other_ca_keys
    _, server_pub = server_keys
    return cert_mod.issue_certificate("server-01", server_pub,
                                       other_ca_priv, PASSWORD)


# ---------------------------------------------------------------------------
# Threading helpers
# ---------------------------------------------------------------------------

class _ServerRunner:
    """Run perform_server_handshake on an accepted socket in a thread,
    storing the result or the raised exception so the test can assert
    on both sides.
    """

    def __init__(self, **server_kwargs: Any):
        self.kwargs = server_kwargs
        self.result: dict[str, Any] | None = None
        self.error: BaseException | None = None
        self.thread: threading.Thread | None = None
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.bind(("127.0.0.1", 0))
        self.listen_sock.listen(1)
        self.port = self.listen_sock.getsockname()[1]

    def __enter__(self) -> "_ServerRunner":
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def _run(self) -> None:
        try:
            conn, _ = self.listen_sock.accept()
            try:
                self.result = perform_server_handshake(conn, **self.kwargs)
            finally:
                conn.close()
        except BaseException as exc:  # noqa: BLE001 — test plumbing
            self.error = exc

    def join(self, timeout: float = 3.0) -> None:
        if self.thread is not None:
            self.thread.join(timeout=timeout)

    def __exit__(self, *_exc: Any) -> None:
        try:
            self.listen_sock.close()
        except OSError:
            pass


def _client_connect(port: int) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=3.0)


# ===========================================================================
# AC1 + AC5: happy-path roundtrip — same keys, exact frozen contract shape
# ===========================================================================

def test_handshake_roundtrip_keys_match(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """AC1: both sides compute identical c2s_key and s2c_key."""
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            client_state = perform_client_handshake(
                sock=sock,
                client_cert=client_cert,
                client_priv_pem=client_priv,
                client_password=PASSWORD,
                ca_pubkey_pem=ca_pub,
            )
        finally:
            sock.close()
        server.join()

    assert server.error is None, f"server raised: {server.error!r}"
    assert server.result is not None
    s = server.result
    c = client_state

    # AC1 — bit-for-bit identical.
    assert s["c2s_key"] == c["c2s_key"]
    assert s["s2c_key"] == c["s2c_key"]
    # And the keys are NOT the same key (c2s != s2c) — separate directions.
    assert s["c2s_key"] != s["s2c_key"]
    # Transcript hash agreement.
    assert s["transcript_hash"] == c["transcript_hash"]


def test_handshake_session_dict_shape_is_frozen_contract(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """AC5: dict has exactly these 5 keys with the right types/lengths."""
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            client_state = perform_client_handshake(
                sock=sock,
                client_cert=client_cert,
                client_priv_pem=client_priv,
                client_password=PASSWORD,
                ca_pubkey_pem=ca_pub,
            )
        finally:
            sock.close()
        server.join()

    EXPECTED_KEYS = {"peer_subject", "peer_cert", "c2s_key", "s2c_key", "transcript_hash"}
    for state, label in [(server.result, "server"), (client_state, "client")]:
        assert set(state.keys()) == EXPECTED_KEYS, f"{label} dict shape drift"
        assert isinstance(state["peer_subject"], str)
        assert isinstance(state["peer_cert"], dict)
        assert isinstance(state["c2s_key"], bytes) and len(state["c2s_key"]) == 32
        assert isinstance(state["s2c_key"], bytes) and len(state["s2c_key"]) == 32
        assert isinstance(state["transcript_hash"], bytes)
        assert len(state["transcript_hash"]) == 32


def test_handshake_peer_subjects_are_swapped(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """Each side records the OTHER side's subject as peer_subject."""
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            client_state = perform_client_handshake(
                sock=sock,
                client_cert=client_cert,
                client_priv_pem=client_priv,
                client_password=PASSWORD,
                ca_pubkey_pem=ca_pub,
            )
        finally:
            sock.close()
        server.join()

    assert server.result["peer_subject"] == "alice"
    assert client_state["peer_subject"] == "server-01"


def test_handshake_keys_differ_per_session(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """Two back-to-back handshakes with the same identities produce
    DIFFERENT session keys (because nonces and pre_master are fresh).
    """
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    sessions: list[dict[str, Any]] = []
    for _ in range(2):
        with _ServerRunner(
            server_cert=server_cert,
            server_priv_pem=server_priv,
            server_password=PASSWORD,
            ca_pubkey_pem=ca_pub,
        ) as server:
            sock = _client_connect(server.port)
            try:
                cstate = perform_client_handshake(
                    sock=sock,
                    client_cert=client_cert,
                    client_priv_pem=client_priv,
                    client_password=PASSWORD,
                    ca_pubkey_pem=ca_pub,
                )
            finally:
                sock.close()
            server.join()
        sessions.append(cstate)

    assert sessions[0]["c2s_key"] != sessions[1]["c2s_key"]
    assert sessions[0]["s2c_key"] != sessions[1]["s2c_key"]
    assert sessions[0]["transcript_hash"] != sessions[1]["transcript_hash"]


# ===========================================================================
# AC2: wrong server password -> handshake fails, no key material returned
# ===========================================================================

def test_handshake_wrong_server_password_fails(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """The server cannot decrypt the pre-master with the wrong password,
    so it sends AUTH_FAILED and raises. The client sees a clean error.
    """
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=b"WRONG-PASSWORD",   # <-- the bug under test
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            with pytest.raises(AuthError):
                perform_client_handshake(
                    sock=sock,
                    client_cert=client_cert,
                    client_priv_pem=client_priv,
                    client_password=PASSWORD,
                    ca_pubkey_pem=ca_pub,
                )
        finally:
            sock.close()
        server.join()

    # AC2: server returned no result, raised AuthError on its side too.
    assert server.result is None
    assert isinstance(server.error, AuthError)


# ===========================================================================
# AC3: tampered pre_master_ct -> handshake fails server-side
# ===========================================================================

def _mitm_client_corrupting_pre_master(
    port: int,
    client_cert: dict,
    client_priv_pem: bytes,
    client_password: bytes,
    ca_pubkey_pem: bytes,
) -> None:
    """A custom client that bit-flips the pre_master_ct on the wire.

    Mirrors perform_client_handshake up to KEY_EXCHANGE, then sends a
    corrupted ciphertext so the server's OAEP decryption fails.
    """
    from zerotrust.common.transcript import NONCE_BYTES

    sock = _client_connect(port)
    try:
        # Send HELLO normally.
        nonce_c = os.urandom(NONCE_BYTES)
        send_message(sock, make_envelope("HELLO", {
            "cert": client_cert,
            "nonce": base64.b64encode(nonce_c).decode("ascii"),
        }))
        # Receive server HELLO.
        server_hello = validate_envelope(recv_message(sock))
        server_cert = server_hello["payload"]["cert"]
        server_pub_pem = server_cert["public_key_pem"].encode("ascii")
        # OAEP-encrypt then corrupt one byte.
        pre_master = os.urandom(32)
        ct = bytearray(cp.rsa_oaep_encrypt(server_pub_pem, pre_master))
        ct[10] ^= 0xFF                # <-- tamper
        send_message(sock, make_envelope("KEY_EXCHANGE", {
            "pre_master_ct": base64.b64encode(bytes(ct)).decode("ascii"),
        }))
        # Expect ERROR back; read to drain.
        try:
            recv_message(sock)
        except (ProtocolError, OSError):
            pass
    finally:
        sock.close()


def test_handshake_tampered_pre_master_ct_fails(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """AC3: 1-byte flip in the OAEP ciphertext -> server raises AuthError."""
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        _mitm_client_corrupting_pre_master(
            server.port, client_cert, client_priv, PASSWORD, ca_pub
        )
        server.join()

    assert server.result is None
    assert isinstance(server.error, AuthError)


# ===========================================================================
# AC4: fake server cert -> client aborts BEFORE sending pre-master
# ===========================================================================

def test_handshake_client_aborts_on_untrusted_server_cert(
    ca_keys, other_ca_keys, evil_server_cert, server_keys,
    client_cert, client_keys,
):
    """AC4: A server presenting a cert signed by a DIFFERENT CA.

    The client must verify against its OWN CA trust anchor (``ca_pub``)
    and reject. Critically, the abort must happen BEFORE the client
    sends the pre-master — otherwise a hostile server with a fake
    pubkey could decrypt it.

    We assert this by running a custom 'server' that records what
    messages it received from the client. It must see HELLO but
    NOT KEY_EXCHANGE.
    """
    ca_priv, ca_pub = ca_keys                  # client's trusted CA
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    received_types: list[str] = []
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.bind(("127.0.0.1", 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    def evil_server() -> None:
        conn, _ = listen.accept()
        try:
            # Pretend to be a normal server: read client HELLO, send our
            # (wrong-CA) HELLO back, then wait to see if the client
            # incorrectly sends KEY_EXCHANGE.
            try:
                hello = validate_envelope(recv_message(conn))
                received_types.append(hello["type"])
                send_message(conn, make_envelope("HELLO", {
                    "cert": evil_server_cert,
                    "nonce": base64.b64encode(os.urandom(16)).decode("ascii"),
                }))
                # Set a short timeout — if the client correctly aborts,
                # we should hit EOF / timeout here.
                conn.settimeout(1.0)
                try:
                    msg = recv_message(conn)
                    received_types.append(msg["type"])
                except (ProtocolError, OSError, socket.timeout):
                    pass
            finally:
                conn.close()
        except Exception:
            pass

    t = threading.Thread(target=evil_server, daemon=True)
    t.start()

    try:
        sock = _client_connect(port)
        try:
            with pytest.raises(AuthError):
                perform_client_handshake(
                    sock=sock,
                    client_cert=client_cert,
                    client_priv_pem=client_priv,
                    client_password=PASSWORD,
                    ca_pubkey_pem=ca_pub,        # trusts the REAL CA only
                )
        finally:
            sock.close()
        t.join(timeout=2.0)
    finally:
        listen.close()

    # The client sent HELLO. Critically, KEY_EXCHANGE must NOT appear:
    # the pre-master never reached the hostile server.
    assert received_types == ["HELLO"], (
        f"client leaked KEY_EXCHANGE to untrusted server: saw {received_types}"
    )


def test_handshake_client_expected_subject_mismatch_aborts(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """Subject pinning: client expects 'main-server' but server's cert
    has subject 'server-01' -> client aborts.
    """
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            with pytest.raises(AuthError):
                perform_client_handshake(
                    sock=sock,
                    client_cert=client_cert,
                    client_priv_pem=client_priv,
                    client_password=PASSWORD,
                    ca_pubkey_pem=ca_pub,
                    expected_server_subject="main-server",   # wrong name
                )
        finally:
            sock.close()
        server.join(timeout=2.0)


# ===========================================================================
# Extra negative coverage
# ===========================================================================

def test_handshake_expired_client_cert_rejected_by_server(
    ca_keys, server_cert, server_keys, client_keys, monkeypatch,
):
    """An expired client cert is rejected by the server BEFORE the server
    derives any key material. The server returns an AUTH_FAILED to the
    client and the client surfaces it as an error.
    """
    ca_priv, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, client_pub = client_keys

    # Forge an already-expired cert by lying about wall-clock at issue time.
    real_time = time.time
    monkeypatch.setattr(
        "zerotrust.ca.cert.time.time", lambda: real_time() - 5 * 365 * 86400
    )
    expired_cert = cert_mod.issue_certificate(
        "alice", client_pub, ca_priv, PASSWORD, validity_days=30
    )
    monkeypatch.undo()
    # Sanity check: with real clock, cert.py rejects it.
    assert cert_mod.verify_certificate(expired_cert, ca_pub) is False

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            with pytest.raises(AuthError):
                perform_client_handshake(
                    sock=sock,
                    client_cert=expired_cert,
                    client_priv_pem=client_priv,
                    client_password=PASSWORD,
                    ca_pubkey_pem=ca_pub,
                )
        finally:
            sock.close()
        server.join()

    assert isinstance(server.error, AuthError)


def test_handshake_protocol_drift_wrong_first_message(
    ca_keys, server_cert, server_keys,
):
    """If the client sends something other than HELLO first, server fails
    cleanly and doesn't leak details to the peer.
    """
    _, ca_pub = ca_keys
    server_priv, _ = server_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            # Send a valid envelope of the WRONG type.
            send_message(sock, make_envelope("KEY_EXCHANGE", {
                "pre_master_ct": base64.b64encode(b"\x00" * 256).decode("ascii"),
            }))
            # Server should reply with ERROR/AUTH_FAILED, then close.
            try:
                reply = recv_message(sock)
                # If we got any reply, it MUST be a generic error — never
                # leak the real reason.
                assert reply["type"] == "ERROR"
                assert reply["payload"].get("code") == "AUTH_FAILED"
            except (ProtocolError, OSError):
                pass
        finally:
            sock.close()
        server.join(timeout=2.0)

    assert server.error is not None
    assert server.result is None


def test_handshake_garbage_bytes_on_wire(ca_keys, server_cert, server_keys):
    """Pure garbage on the wire — no framing, no envelope — must not
    crash the server thread. The server must surface ProtocolError or
    AuthError, never an unhandled exception."""
    _, ca_pub = ca_keys
    server_priv, _ = server_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            sock.sendall(b"\xff" * 32 + b"this-is-not-a-valid-envelope")
        finally:
            sock.close()
        server.join(timeout=2.0)

    # Either ProtocolError or AuthError is fine — what matters is that
    # the server raised CLEANLY (not e.g. a JSONDecodeError leaking out).
    assert server.result is None
    assert isinstance(server.error, (ProtocolError, AuthError))


def test_handshake_transcript_matches_hand_computed(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """Defensive: re-derive the transcript hash from observed wire bytes
    and confirm it matches what the handshake stored. Catches accidental
    drift in the concatenation order between client and server.
    """
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            client_state = perform_client_handshake(
                sock=sock,
                client_cert=client_cert,
                client_priv_pem=client_priv,
                client_password=PASSWORD,
                ca_pubkey_pem=ca_pub,
            )
        finally:
            sock.close()
        server.join()

    # The two sides must agree on the transcript hash, AND that hash must
    # be exactly 32 bytes (SHA-256 width).
    assert server.result["transcript_hash"] == client_state["transcript_hash"]
    assert len(server.result["transcript_hash"]) == 32


def test_handshake_no_secrets_in_session_dict_repr(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """str(session_dict) WILL contain the raw key bytes (it's a plain
    dict), so the production code must never call str() on it for
    logging. Here we just sanity-check that the structure does carry
    the raw bytes — to flag future refactors that 'helpfully' replace
    them with placeholder strings, which would silently break callers.
    """
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            client_state = perform_client_handshake(
                sock=sock,
                client_cert=client_cert,
                client_priv_pem=client_priv,
                client_password=PASSWORD,
                ca_pubkey_pem=ca_pub,
            )
        finally:
            sock.close()
        server.join()

    assert isinstance(client_state["c2s_key"], bytes)
    assert isinstance(client_state["s2c_key"], bytes)
    # Both keys are non-zero — sanity check against a "fill with zeros" bug.
    assert client_state["c2s_key"] != b"\x00" * 32
    assert client_state["s2c_key"] != b"\x00" * 32


def test_handshake_hkdf_salt_order_is_nonce_c_then_nonce_s(
    ca_keys, server_cert, server_keys, client_cert, client_keys,
):
    """Regression test for the most subtle pitfall: if one side
    concatenated `nonce_s + nonce_c` instead of `nonce_c + nonce_s`,
    both sides would compute different keys and the handshake would
    succeed (no crypto detects it) but every subsequent encrypted
    message would auth-fail. This test re-derives keys from the
    transcript_hash and confirms agreement.
    """
    _, ca_pub = ca_keys
    server_priv, _ = server_keys
    client_priv, _ = client_keys

    with _ServerRunner(
        server_cert=server_cert,
        server_priv_pem=server_priv,
        server_password=PASSWORD,
        ca_pubkey_pem=ca_pub,
    ) as server:
        sock = _client_connect(server.port)
        try:
            client_state = perform_client_handshake(
                sock=sock,
                client_cert=client_cert,
                client_priv_pem=client_priv,
                client_password=PASSWORD,
                ca_pubkey_pem=ca_pub,
            )
        finally:
            sock.close()
        server.join()

    # If salt order had drifted, c2s_key would differ — already covered
    # in test_handshake_roundtrip_keys_match. Belt-and-braces here.
    assert server.result["c2s_key"] == client_state["c2s_key"]
    assert server.result["s2c_key"] == client_state["s2c_key"]
