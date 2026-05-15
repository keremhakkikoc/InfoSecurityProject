"""Client helper for fetching another user's CA-signed cert from the
server's pubkey directory.

The returned cert is verified against the LOCAL CA trust anchor before
returning, so the server is treated as an untrusted relay — this is the
zero-trust property of the directory.
"""

from __future__ import annotations

import socket

from zerotrust.ca.cert import verify_certificate
from zerotrust.common.exceptions import AuthError, ProtocolError
from zerotrust.common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)


def fetch_peer_cert(
    sock: socket.socket,
    ca_pubkey_pem: bytes,
    username: str,
) -> dict:
    """Ask the server for ``username``'s cert; verify locally; return dict.

    Args:
        sock: an already-connected socket to the server. (Future PRs may
            require this socket to be inside an authenticated session;
            for #21 we keep the dependency loose so unit tests don't
            need a full handshake.)
        ca_pubkey_pem: the local CA trust anchor PEM bytes.
        username: subject to fetch.

    Returns:
        The cert dict (after subject + signature verification).

    Raises:
        AuthError: server returned NOT_FOUND, or the cert it sent fails
            local verification, or the returned subject doesn't match.
        ProtocolError: malformed envelope on the wire.
    """
    send_message(sock, make_envelope("GET_PUBKEY", {"username": username}))

    response = validate_envelope(recv_message(sock))
    if response["type"] == "ERROR":
        code = response["payload"].get("code", "UNKNOWN")
        raise AuthError(f"GET_PUBKEY failed: {code}")
    if response["type"] != "PUBKEY_RESPONSE":
        raise ProtocolError(
            f"expected PUBKEY_RESPONSE, got {response['type']!r}"
        )

    cert = response["payload"].get("cert")
    if not isinstance(cert, dict):
        raise ProtocolError("PUBKEY_RESPONSE missing cert dict")

    # Zero-trust: never accept the server's word — verify against our
    # OWN CA trust anchor, AND require the subject to match what we asked
    # for (defeats a hostile server swapping certs).
    if not verify_certificate(cert, ca_pubkey_pem, expected_subject=username):
        raise AuthError(
            f"peer cert for {username!r} failed local CA verification"
        )
    return cert