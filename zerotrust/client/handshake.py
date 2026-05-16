"""Client-side handshake state machine per ARCHITECTURE.md §7.4 + §7.5.

Mirrors ``zerotrust/server/handshake.py``. The client opens the socket,
performs the HELLO exchange, generates a 32-byte pre-master, wraps it
under the server's pubkey with RSA-OAEP, signs the transcript hash to
prove possession of its private key, and verifies the server's PoP
from SESSION_OK before considering the handshake live.

Returns the same frozen session-state dict shape as the server.
"""

from __future__ import annotations

import base64
import os
import socket
from typing import Any

from ..ca.cert import verify_certificate
from ..common.crypto_primitives import (
    hkdf_derive,
    rsa_oaep_encrypt,
    rsa_sign,
    rsa_verify,
)
from ..common.exceptions import AuthError, ProtocolError
from ..common.logger import fingerprint, get_logger
from ..common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from ..common.transcript import NONCE_BYTES, build_transcript_hash

# Must match server side. ARCHITECTURE.md §7.5 freezes these.
HKDF_INFO = b"zerotrust-v1"
HKDF_OUTPUT_BYTES = 64
SESSION_KEY_BYTES = 32
PRE_MASTER_BYTES = 32


def perform_client_handshake(
    sock: socket.socket,
    client_cert: dict,
    client_priv_pem: bytes,
    client_password: bytes,
    ca_pubkey_pem: bytes,
    expected_server_subject: str | None = None,
) -> dict[str, Any]:
    """Run the client side of the handshake.

    Args:
        sock: an already-connected TCP socket to the server.
        client_cert: the client's CA-signed cert dict (sent in HELLO).
        client_priv_pem: client's password-encrypted private key.
        client_password: password for the private key.
        ca_pubkey_pem: CA trust anchor used to verify the server's cert.
        expected_server_subject: if given, the server's cert subject MUST
            match this string exactly. Use this when the client knows in
            advance which named server it expects to reach.

    Returns the session-state dict:

        {
            "peer_subject":    str,    # verified server subject
            "peer_cert":       dict,   # the full verified server cert
            "c2s_key":         bytes,  # 32 bytes
            "s2c_key":         bytes,  # 32 bytes
            "transcript_hash": bytes,  # 32 bytes
        }

    Raises:
        AuthError: server cert or PoP signature did not verify. NO key
            material is returned; caller MUST close the socket.
        ProtocolError: malformed envelope / wrong message type.

    Importantly, this function aborts with ``AuthError`` **before**
    sending the pre-master if the server cert fails to verify — so a
    misconfigured (or hostile) server never sees our pre-master.
    """
    log = get_logger("client.handshake")

    # --- Step 1: send client HELLO -------------------------------------
    nonce_c = os.urandom(NONCE_BYTES)
    client_hello = make_envelope("HELLO", {
        "cert": client_cert,
        "nonce": base64.b64encode(nonce_c).decode("ascii"),
    })
    send_message(sock, client_hello)

    # --- Step 2: receive server HELLO and verify cert ------------------
    server_hello = validate_envelope(recv_message(sock))
    if server_hello["type"] != "HELLO":
        # Could be ERROR (server rejected our cert) — surface as AuthError.
        raise AuthError(f"expected HELLO from server, got {server_hello['type']!r}")

    payload = server_hello["payload"]
    if not isinstance(payload, dict) or "cert" not in payload or "nonce" not in payload:
        raise ProtocolError("server HELLO payload missing cert/nonce")

    server_cert = payload["cert"]
    try:
        nonce_s = base64.b64decode(payload["nonce"], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError("server nonce not valid base64") from exc

    if len(nonce_s) != NONCE_BYTES:
        raise ProtocolError(f"server nonce wrong length: {len(nonce_s)}")

    # CRITICAL: abort BEFORE sending the pre-master if cert is bad.
    # A hostile server with a fake cert must never see our pre-master,
    # even though it's OAEP-wrapped (their fake pubkey could decrypt it).
    if not verify_certificate(server_cert, ca_pubkey_pem,
                              expected_subject=expected_server_subject):
        log.warning("server cert verification failed — aborting before KEY_EXCHANGE")
        raise AuthError("server cert verification failed")

    peer_subject = server_cert["subject"]
    server_pubkey_pem = server_cert["public_key_pem"].encode("ascii")
    log.info("server HELLO verified peer=%s fp=%s",
             peer_subject, fingerprint(server_pubkey_pem))

    # --- Step 3: send KEY_EXCHANGE -------------------------------------
    pre_master = os.urandom(PRE_MASTER_BYTES)
    pre_master_ct = rsa_oaep_encrypt(server_pubkey_pem, pre_master)
    key_ex = make_envelope("KEY_EXCHANGE", {
        "pre_master_ct": base64.b64encode(pre_master_ct).decode("ascii"),
    })
    send_message(sock, key_ex)

    # --- Step 4: compute the binding transcript and sign it ------------
    transcript = build_transcript_hash(nonce_c, nonce_s, pre_master_ct)
    client_sig = rsa_sign(client_priv_pem, client_password, transcript)

    # --- Step 5: send AUTH_RESPONSE ------------------------------------
    auth_resp = make_envelope("AUTH_RESPONSE", {
        "signature": base64.b64encode(client_sig).decode("ascii"),
    })
    send_message(sock, auth_resp)

    # --- Step 6: receive SESSION_OK and verify server PoP --------------
    try:
        session_ok = validate_envelope(recv_message(sock))
    except OSError as exc:
        raise AuthError("server closed connection during authentication") from exc
    if session_ok["type"] != "SESSION_OK":
        # Could be ERROR (server rejected our PoP).
        raise AuthError(f"expected SESSION_OK, got {session_ok['type']!r}")

    try:
        server_sig = base64.b64decode(
            session_ok["payload"]["signature"], validate=True
        )
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError("server signature not valid base64") from exc

    if not rsa_verify(server_pubkey_pem, transcript, server_sig):
        log.warning("server PoP signature invalid")
        raise AuthError("server PoP signature invalid")

    # --- Step 7: derive session keys via HKDF --------------------------
    okm = hkdf_derive(
        ikm=pre_master,
        salt=nonce_c + nonce_s,           # MUST match server's ordering.
        info=HKDF_INFO,
        length=HKDF_OUTPUT_BYTES,
    )
    c2s_key = okm[:SESSION_KEY_BYTES]
    s2c_key = okm[SESSION_KEY_BYTES:]

    log.info(
        "session established peer=%s peer_fp=%s transcript_fp=%s",
        peer_subject,
        fingerprint(server_pubkey_pem),
        fingerprint(transcript),
    )

    return {
        "peer_subject":    peer_subject,
        "peer_cert":       server_cert,
        "c2s_key":         c2s_key,
        "s2c_key":         s2c_key,
        "transcript_hash": transcript,
    }
