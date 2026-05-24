"""Audit-log regression suite (issue #20).

This file is the single canonical proof that the server's audit logging
honours both the *format contract* (ARCHITECTURE.md §9 severity matrix +
mandatory ``event=...`` shape) AND the *isolation contract* (AI.md §3.25
— no private keys, plaintext, session keys, AES file keys, full
signatures, or passwords in any log line).

The tests drive the real server through a ``ThreadingTCPServer`` thread
and inspect ``caplog.text`` after each scenario. We do *not* mock the
logger — the goal is to catch a careless ``logger.debug(f"...{c2s_key}")``
the moment it is introduced anywhere in the call graph.

Forbidden-list regex (used by ``test_full_flow_caplog_has_no_secrets``):

    BEGIN PRIVATE KEY      — full PEM never appears
    password=              — neither demo nor env passwords appear
    c2s_key=  / s2c_key=   — handshake session keys never appear
    aes_key=  / file_key=  — unwrapped per-file AES keys never appear
    plaintext=             — decrypted file content never appears
    pre_master=            — handshake pre-master never appears
    transcript_hash=       — raw transcript bytes never appear (fingerprint OK)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import socket
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
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import AuthError, CryptoError, ProtocolError
from zerotrust.common.file_crypto import encrypt_file_blob
from zerotrust.common.key_wrap import wrap_aes_key_for
from zerotrust.common.logger import audit, audit_info, fingerprint
from zerotrust.common.origin import sign_origin_struct
from zerotrust.common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from zerotrust.server.main import ZeroTrustRequestHandler, ZeroTrustServer

CA_PASSWORD = b"ca-audit-password"
SERVER_PASSWORD = b"server-audit-password"
ALICE_PASSWORD = b"alice-audit-password"
BOB_PASSWORD = b"bob-audit-password"
MALLORY_PASSWORD = b"mallory-audit-password"

# The Forbidden list from the issue body. We compile it once so the test
# is deterministic and so adding to the list is a one-line change.
# IMPORTANT: each pattern must match a *value leak*, not the legitimate
# audit field names themselves (we never emit ``aes_key=...``; the
# pattern guards against a future regression).
_FORBIDDEN_PATTERNS = re.compile(
    r"(BEGIN PRIVATE KEY"
    r"|password="
    r"|c2s_key="
    r"|s2c_key="
    r"|aes_key="
    r"|file_key="
    r"|plaintext="
    r"|pre_master="
    r"|transcript_hash=)"
)


# ---------------------------------------------------------------------------
# Fixture environment — kept minimal; we only need alice (sender), bob
# (recipient), mallory (forger).
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
def _alice_socket(env: _Env, port: int) -> Iterator[socket.socket]:
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
) -> tuple[dict[str, Any], str, bytes, bytes]:
    """Return ``(payload, file_id, ciphertext, wrapped_key)``.

    Returns the raw ciphertext + wrapped key so the test can sanity-check
    that those bytes did NOT end up in the audit text after the request
    was rejected — the strongest possible isolation assertion.
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
    expiration = timestamp + 3600

    sig_priv = signing_priv if signing_priv is not None else env.alice_priv
    signature = sign_origin_struct(
        sig_priv, signing_password,
        sender=sender, recipient=recipient, file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp, expiration=expiration,
    )

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
    return payload, file_id, ciphertext, wrapped_key


def _send_and_recv(sock: socket.socket, payload: dict[str, Any]) -> dict[str, Any]:
    send_message(sock, make_envelope("UPLOAD_REQUEST", payload))
    return validate_envelope(recv_message(sock))


# ---------------------------------------------------------------------------
# 1. logger helper unit tests — no network involved.
# ---------------------------------------------------------------------------

class TestAuditHelper:
    """The :func:`audit` helper is the redaction chokepoint. If these
    tests pass, the call-site behaviour in handler/handshake follows."""

    def test_bytes_are_fingerprinted_not_logged_raw(self, caplog):
        log = logging.getLogger("zerotrust.test.audit")
        secret = b"\x00\x01" * 64  # 128 bytes of "key material"
        with caplog.at_level(logging.INFO, logger="zerotrust.test.audit"):
            audit_info(log, "demo_event", payload=secret)
        # The raw bytes (or anything that looks like them) must NOT appear.
        assert "\\x00\\x01" not in caplog.text
        # Instead, a fingerprint MUST be present.
        assert f"fp={fingerprint(secret)}" in caplog.text

    def test_forbidden_field_names_are_redacted(self, caplog):
        log = logging.getLogger("zerotrust.test.audit2")
        with caplog.at_level(logging.INFO, logger="zerotrust.test.audit2"):
            audit_info(
                log,
                "demo_event",
                # All of these field names live on the Forbidden list.
                c2s_key=b"\xaa" * 32,
                s2c_key="should-not-leak",
                aes_key=b"\xbb" * 32,
                password="hunter2",
                pre_master=b"\xcc" * 32,
                public_key_pem="-----BEGIN PUBLIC KEY-----\nxxx\n-----END...",
            )
        # Every forbidden field name renders as ``<name>=<redacted>``.
        for forbidden in ("c2s_key", "s2c_key", "aes_key", "password",
                          "pre_master", "public_key_pem"):
            assert f"{forbidden}=<redacted>" in caplog.text
        # And none of the actual values leak through.
        for leaked in ("hunter2", "BEGIN PUBLIC KEY", "should-not-leak"):
            assert leaked not in caplog.text

    def test_long_strings_are_truncated(self, caplog):
        log = logging.getLogger("zerotrust.test.audit3")
        flood = "A" * 4096
        with caplog.at_level(logging.INFO, logger="zerotrust.test.audit3"):
            audit_info(log, "demo_event", note=flood)
        assert "[truncated]" in caplog.text
        # The full 4096-A string must NOT be present.
        assert flood not in caplog.text

    def test_event_field_always_present(self, caplog):
        log = logging.getLogger("zerotrust.test.audit4")
        with caplog.at_level(logging.INFO, logger="zerotrust.test.audit4"):
            audit(log, logging.INFO, "ev_x", whatever="value")
        # Every audit line starts with event=<id> so the grader can grep
        # ``event=`` and see one row per audited action.
        assert "event=ev_x" in caplog.text

    def test_cert_dict_logs_only_fingerprint(self, caplog):
        """ARCHITECTURE.md §9: cert pubkeys logged as 16-hex fingerprint,
        never the full PEM. Matches issue acceptance bullet:
        'when we log a cert dict, only the fingerprint(...) is emitted,
        never the full public_key_pem'."""
        from zerotrust.server.handler import _cert_fp
        cert = {
            "subject": "alice",
            "public_key_pem":
                "-----BEGIN PUBLIC KEY-----\nABCDEFG\n-----END PUBLIC KEY-----\n",
        }
        log = logging.getLogger("zerotrust.test.audit5")
        with caplog.at_level(logging.INFO, logger="zerotrust.test.audit5"):
            audit_info(log, "cert_log", subject=cert["subject"], fp=_cert_fp(cert))
        assert "BEGIN PUBLIC KEY" not in caplog.text
        assert len(_cert_fp(cert)) == 16
        assert f"fp={_cert_fp(cert)}" in caplog.text


# ---------------------------------------------------------------------------
# 2. Required test: happy upload → INFO event=upload_accept with file_id
# ---------------------------------------------------------------------------

def test_happy_upload_logs_info_upload_accept(env, caplog):
    with caplog.at_level(logging.INFO, logger="zerotrust"):
        with _running_server(env) as port:
            with _alice_socket(env, port) as sock:
                payload, file_id, _, _ = _build_upload_payload(env, plaintext=b"hi")
                reply = _send_and_recv(sock, payload)

    assert reply["type"] == "UPLOAD_ACK"
    # The INFO accept line must exist, must include the right file_id, and
    # must use the structured ``event=upload_accept`` prefix per the
    # acceptance criteria.
    accept_lines = [
        r for r in caplog.records
        if r.levelno == logging.INFO and "event=upload_accept" in r.message
    ]
    assert accept_lines, f"no INFO event=upload_accept line:\n{caplog.text}"
    assert any(f"file_id={file_id}" in r.message for r in accept_lines)
    assert any("sender=alice" in r.message for r in accept_lines)
    assert any("recipient=bob" in r.message for r in accept_lines)
    # AND a fingerprint, not a full PEM, must accompany it.
    assert any("sender_fp=" in r.message for r in accept_lines)


# ---------------------------------------------------------------------------
# 3. Required test: forged upload → ERROR event=origin_sig_fail AND
#    the raw signature bytes are absent from caplog.text.
# ---------------------------------------------------------------------------

def test_forged_upload_logs_error_origin_sig_fail_without_raw_signature(env, caplog):
    with caplog.at_level(logging.WARNING, logger="zerotrust"):
        with _running_server(env) as port:
            with _alice_socket(env, port) as sock:
                # Mallory signs but session-proven identity is alice → sig fails
                payload, file_id, _, _ = _build_upload_payload(
                    env,
                    signing_priv=env.mallory_priv,
                    signing_password=MALLORY_PASSWORD,
                )
                reply = _send_and_recv(sock, payload)

    assert reply["type"] == "ERROR"
    assert reply["payload"]["code"] == "AUTH_FAILED"

    err_records = [r for r in caplog.records if r.levelno == logging.ERROR]
    sig_fail = [r for r in err_records if "event=origin_sig_fail" in r.message]
    assert sig_fail, f"no ERROR event=origin_sig_fail line:\n{caplog.text}"
    assert any(f"file_id={file_id}" in r.message for r in sig_fail)

    # The raw signature bytes from payload["signature"] must be absent.
    raw_signature_b64 = payload["signature"]
    assert raw_signature_b64 not in caplog.text


# ---------------------------------------------------------------------------
# 4. Required test: replay → WARNING event=replay_reject with nonce_fp only.
# ---------------------------------------------------------------------------

def test_replay_logs_warning_replay_reject_with_nonce_fp_only(env, caplog):
    with caplog.at_level(logging.INFO, logger="zerotrust"):
        with _running_server(env) as port:
            with _alice_socket(env, port) as sock:
                payload, _, _, _ = _build_upload_payload(env)
                envelope = make_envelope("UPLOAD_REQUEST", payload)

                send_message(sock, envelope)
                first = validate_envelope(recv_message(sock))
                assert first["type"] == "UPLOAD_ACK"

                send_message(sock, envelope)
                second = validate_envelope(recv_message(sock))

    assert second["type"] == "ERROR"
    assert second["payload"]["code"] in {"STALE", "REPLAY"}

    replay_lines = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "event=replay_reject" in r.message
    ]
    assert replay_lines, f"no WARNING event=replay_reject line:\n{caplog.text}"
    assert any("nonce_fp=" in r.message for r in replay_lines)

    # The raw nonce (base64 form) from the replayed envelope must not
    # appear anywhere in the audit text — only its fingerprint.
    raw_nonce_b64 = envelope["nonce"]
    assert raw_nonce_b64 not in caplog.text


# ---------------------------------------------------------------------------
# 5. Required test: scan the entire caplog.text after a full upload flow
#    with the Forbidden regex — must produce 0 matches.
# ---------------------------------------------------------------------------

def test_full_flow_caplog_has_no_secrets(env, caplog):
    """End-to-end isolation guarantee. Drives one happy upload, one
    forged upload, and one replay through the server, then asserts that
    the Forbidden-list regex finds NOTHING in the captured audit stream.

    This is the same intent as the acceptance bullet
    ``grep -E '(BEGIN PRIVATE KEY|password=|c2s_key=|aes_key=|plaintext=)'
    server/logs/audit.log`` returns nothing — but mechanised through
    ``caplog`` so it runs in CI."""

    plaintext_payload = b"the actual plaintext that must NOT be logged"

    with caplog.at_level(logging.DEBUG, logger="zerotrust"):
        with _running_server(env) as port:
            with _alice_socket(env, port) as sock:
                payload, _, _, _ = _build_upload_payload(
                    env, plaintext=plaintext_payload,
                )
                reply = _send_and_recv(sock, payload)
                assert reply["type"] == "UPLOAD_ACK"

            # Forged
            with _alice_socket(env, port) as sock:
                payload, _, _, _ = _build_upload_payload(
                    env,
                    plaintext=plaintext_payload,
                    signing_priv=env.mallory_priv,
                    signing_password=MALLORY_PASSWORD,
                )
                reply = _send_and_recv(sock, payload)
                assert reply["payload"]["code"] == "AUTH_FAILED"

            # Replay
            with _alice_socket(env, port) as sock:
                payload, _, _, _ = _build_upload_payload(
                    env, plaintext=plaintext_payload,
                )
                envelope = make_envelope("UPLOAD_REQUEST", payload)
                send_message(sock, envelope)
                _ = validate_envelope(recv_message(sock))
                send_message(sock, envelope)
                second = validate_envelope(recv_message(sock))
                assert second["payload"]["code"] in {"STALE", "REPLAY"}

    matches = _FORBIDDEN_PATTERNS.findall(caplog.text)
    assert not matches, (
        f"Forbidden pattern(s) found in audit log: {matches!r}\n"
        f"Full log was:\n{caplog.text}"
    )

    # And the plaintext itself must never appear.
    assert plaintext_payload.decode() not in caplog.text

    # The configured passwords (test fixtures) must never appear.
    for pw in (CA_PASSWORD, SERVER_PASSWORD, ALICE_PASSWORD,
               BOB_PASSWORD, MALLORY_PASSWORD):
        assert pw.decode() not in caplog.text


# ---------------------------------------------------------------------------
# 6. Bonus: handshake_fail line is emitted at WARNING when a client
#    fails proof-of-possession (matches issue's "Every replay/stale/
#    auth-fail logs at WARNING").
# ---------------------------------------------------------------------------

def test_failed_handshake_logs_warning_handshake_fail(env, caplog):
    """A client that connects with a CA-signed cert but no matching
    private key (we forge the signature) must fail handshake at the PoP
    step and produce a WARNING event=handshake_fail line on the server."""
    with caplog.at_level(logging.WARNING, logger="zerotrust"):
        with _running_server(env) as port:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                # Use alice's *cert* but sign with mallory's *key* — PoP fails.
                # The client handshake surfaces this as AuthError / ProtocolError /
                # CryptoError depending on whether the server closes first; any
                # of the three counts as the expected failure mode here.
                with pytest.raises((AuthError, ProtocolError, CryptoError, OSError)):
                    perform_client_handshake(
                        sock=sock,
                        client_cert=env.alice_cert,
                        client_priv_pem=env.mallory_priv,
                        client_password=MALLORY_PASSWORD,
                        ca_pubkey_pem=env.ca_pub,
                        expected_server_subject="zerotrust-server",
                    )
            finally:
                sock.close()
            # Give the server thread a moment to log the failure before
            # the test harness tears it down.
            time.sleep(0.1)

    fail_lines = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "event=handshake_fail" in r.message
    ]
    assert fail_lines, f"no WARNING event=handshake_fail line:\n{caplog.text}"
