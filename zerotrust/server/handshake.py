"""Server-side handshake state machine per ARCHITECTURE.md §7.4 + §7.5.

This is the load-bearing piece of M2: every subsequent issue (upload,
download, signed metadata, audit logging) assumes both peers walked
through this function and ended up with the same ``c2s_key``/``s2c_key``.

The shape of the returned dict is **frozen** — Phase 2/3 callers index
into it by name. Adding or renaming a key is a breaking change.
"""

from __future__ import annotations

import base64
import os
import socket
from typing import Any

from ..ca.cert import verify_certificate
from ..common.crypto_primitives import (
    hkdf_derive,
    rsa_oaep_decrypt,
    rsa_sign,
    rsa_verify,
)
from ..common.exceptions import AuthError, CryptoError, ProtocolError
from ..common.logger import (
    audit_info,
    audit_warning,
    fingerprint,
    get_logger,
)
from ..common.protocol import (
    make_envelope,
    pack_message,
    recv_message,
    send_message,
    validate_envelope,
)
from ..common.transcript import NONCE_BYTES, build_transcript_hash

# Frozen by ARCHITECTURE.md §7.5 — both sides must use these exact values.
HKDF_INFO = b"zerotrust-v1"
HKDF_OUTPUT_BYTES = 64
SESSION_KEY_BYTES = 32
PRE_MASTER_BYTES = 32

# Generic error code sent to the peer on ANY failure during the handshake.
# We MUST NOT leak the underlying reason.
_GENERIC_AUTH_FAILED = "AUTH_FAILED"


def _send_error(sock: socket.socket, code: str) -> None:
    """Best-effort generic error to the peer. Swallow socket errors; the
    caller will close the socket anyway."""
    try:
        sock.sendall(pack_message(make_envelope("ERROR", {"code": code})))
    except OSError:
        pass


def _fail(
    sock: socket.socket,
    log,
    reason: str,
    *,
    exc: Exception | None = None,
    peer_subject: str | None = None,
    peer_fp: str | None = None,
) -> None:
    """Log the *real* reason server-side, send generic AUTH_FAILED to peer,
    then raise AuthError so the caller closes the socket.

    The audit event uses ``event=handshake_fail`` so the regression test
    can grep for it deterministically. The *reason* string is a fixed
    server-side identifier (e.g. ``client_cert_invalid``) — never derived
    from peer-controlled bytes.
    """
    audit_warning(
        log,
        "handshake_fail",
        reason=reason,
        peer=peer_subject,
        fp=peer_fp,
        err_type=type(exc).__name__ if exc is not None else None,
    )
    _send_error(sock, _GENERIC_AUTH_FAILED)
    raise AuthError(reason) from exc


def perform_server_handshake(
    sock: socket.socket,
    server_cert: dict,
    server_priv_pem: bytes,
    server_password: bytes,
    ca_pubkey_pem: bytes,
) -> dict[str, Any]:
    """Run the server side of the handshake.

    Returns the negotiated session state:

        {
            "peer_subject":    str,    # the verified client subject
            "peer_cert":       dict,   # the full verified client cert
            "c2s_key":         bytes,  # 32 bytes, client → server traffic
            "s2c_key":         bytes,  # 32 bytes, server → client traffic
            "transcript_hash": bytes,  # 32 bytes, SHA-256 transcript binding
        }

    Raises:
        AuthError: peer cert verification, decryption, or PoP verification
            failed. The caller MUST close the socket.
        ProtocolError: malformed envelope / wrong message type.

    On any failure a generic ``AUTH_FAILED`` envelope is sent to the peer
    before the exception propagates, so the client receives a clean error
    instead of a half-finished handshake.
    """
    log = get_logger("server.handshake")

    # --- Step 1: receive client HELLO ----------------------------------
    try:
        hello = validate_envelope(recv_message(sock))
    except ProtocolError as exc:
        _fail(sock, log, f"malformed client HELLO: {exc}", exc=exc)

    if hello["type"] != "HELLO":
        _fail(sock, log, f"expected HELLO, got {hello['type']!r}")

    payload = hello["payload"]
    if not isinstance(payload, dict) or "cert" not in payload or "nonce" not in payload:
        _fail(sock, log, "client HELLO payload missing cert/nonce")

    client_cert = payload["cert"]
    try:
        nonce_c = base64.b64decode(payload["nonce"], validate=True)
    except Exception as exc:  # noqa: BLE001
        _fail(sock, log, "client nonce not valid base64", exc=exc)

    if len(nonce_c) != NONCE_BYTES:
        _fail(sock, log, f"client nonce wrong length: {len(nonce_c)}")

    # --- Step 2: verify client cert against CA -------------------------
    if not verify_certificate(client_cert, ca_pubkey_pem):
        # We DON'T pin subject server-side — anyone CA-signed can connect.
        # Subject is recorded for downstream auth (upload sender pinning).
        _fail(sock, log, "client cert verification failed")

    peer_subject = client_cert["subject"]
    client_pubkey_pem = client_cert["public_key_pem"].encode("ascii")
    peer_fp = fingerprint(client_pubkey_pem)
    audit_info(
        log,
        "handshake_hello",
        peer=peer_subject,
        fp=peer_fp,
    )

    # --- Step 3: send server HELLO -------------------------------------
    nonce_s = os.urandom(NONCE_BYTES)
    server_hello = make_envelope("HELLO", {
        "cert": server_cert,
        "nonce": base64.b64encode(nonce_s).decode("ascii"),
    })
    send_message(sock, server_hello)

    # --- Step 4: receive KEY_EXCHANGE and decrypt pre-master -----------
    try:
        key_ex = validate_envelope(recv_message(sock))
    except ProtocolError as exc:
        _fail(sock, log, f"malformed KEY_EXCHANGE: {exc}", exc=exc)

    if key_ex["type"] != "KEY_EXCHANGE":
        _fail(sock, log, f"expected KEY_EXCHANGE, got {key_ex['type']!r}")

    try:
        pre_master_ct = base64.b64decode(
            key_ex["payload"]["pre_master_ct"], validate=True
        )
    except Exception as exc:  # noqa: BLE001
        _fail(sock, log, "pre_master_ct not valid base64", exc=exc)

    try:
        pre_master = rsa_oaep_decrypt(server_priv_pem, server_password, pre_master_ct)
    except CryptoError as exc:
        _fail(sock, log, "pre_master OAEP decryption failed", exc=exc)

    if len(pre_master) != PRE_MASTER_BYTES:
        # Client sent a wrong-sized pre-master under our pubkey. Treat as
        # adversarial — generic AUTH_FAILED, no detail to peer.
        _fail(sock, log, f"pre_master wrong length: {len(pre_master)}")

    # --- Step 5: compute the binding transcript ------------------------
    transcript = build_transcript_hash(nonce_c, nonce_s, pre_master_ct)

    # --- Step 6: receive AUTH_RESPONSE and verify client PoP -----------
    try:
        auth_resp = validate_envelope(recv_message(sock))
    except ProtocolError as exc:
        _fail(sock, log, f"malformed AUTH_RESPONSE: {exc}", exc=exc)

    if auth_resp["type"] != "AUTH_RESPONSE":
        _fail(sock, log, f"expected AUTH_RESPONSE, got {auth_resp['type']!r}")

    try:
        client_sig = base64.b64decode(
            auth_resp["payload"]["signature"], validate=True
        )
    except Exception as exc:  # noqa: BLE001
        _fail(sock, log, "client signature not valid base64", exc=exc)

    if not rsa_verify(client_pubkey_pem, transcript, client_sig):
        _fail(
            sock,
            log,
            "client_pop_signature_invalid",
            peer_subject=peer_subject,
            peer_fp=peer_fp,
        )

    # --- Step 7: derive session keys via HKDF --------------------------
    okm = hkdf_derive(
        ikm=pre_master,
        salt=nonce_c + nonce_s,           # ORDER MATTERS — both sides agree.
        info=HKDF_INFO,
        length=HKDF_OUTPUT_BYTES,
    )
    c2s_key = okm[:SESSION_KEY_BYTES]
    s2c_key = okm[SESSION_KEY_BYTES:]

    # --- Step 8: send SESSION_OK with server PoP -----------------------
    server_sig = rsa_sign(server_priv_pem, server_password, transcript)
    session_ok = make_envelope("SESSION_OK", {
        "signature": base64.b64encode(server_sig).decode("ascii"),
    })
    send_message(sock, session_ok)

    audit_info(
        log,
        "handshake_ok",
        peer=peer_subject,
        fp=peer_fp,
        transcript_fp=fingerprint(transcript),
    )

    # --- Step 9: return the frozen session-state dict ------------------
    return {
        "peer_subject":    peer_subject,
        "peer_cert":       client_cert,
        "c2s_key":         c2s_key,
        "s2c_key":         s2c_key,
        "transcript_hash": transcript,
    }
