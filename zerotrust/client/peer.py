"""Client-side public-key directory lookup.

Before encrypting a file for *bob*, the sender needs Bob's CA-signed
certificate so the AES key can be wrapped under Bob's pubkey (#11a). The
server stores a pubkey directory which we query with ``GET_PUBKEY``; the
response is locally CA-verified — never trust what the server hands back
without re-running ``verify_certificate``.
"""

from __future__ import annotations

from typing import Any

from ..ca.cert import verify_certificate
from ..common.exceptions import AuthError, ProtocolError
from ..common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)


def fetch_peer_cert(session: dict[str, Any], username: str) -> dict[str, Any]:
    """Fetch and locally verify ``username``'s CA-signed certificate.

    ``session`` must be a live session dict from
    :func:`zerotrust.client.session.connected_session` — it carries both
    the open ``sock`` and the trusted ``ca_pubkey_pem`` used to verify the
    response.

    Raises:
        ProtocolError: malformed reply or server returned ``ERROR``
            (``NOT_FOUND`` for unknown recipients).
        AuthError: the returned cert did not verify against the CA, or
            its subject did not match ``username``.
    """
    sock = session.get("sock")
    ca_pubkey_pem = session.get("ca_pubkey_pem")
    if sock is None or not isinstance(ca_pubkey_pem, (bytes, bytearray)):
        raise ProtocolError("live client session is required")

    send_message(sock, make_envelope("GET_PUBKEY", {"username": username}))
    reply = validate_envelope(recv_message(sock))

    if reply["type"] == "ERROR":
        code = reply["payload"].get("code", "ERROR")
        raise ProtocolError(str(code))
    if reply["type"] != "PUBKEY_RESPONSE":
        raise ProtocolError(f"expected PUBKEY_RESPONSE, got {reply['type']!r}")

    cert = reply["payload"].get("cert")
    if not isinstance(cert, dict):
        raise ProtocolError("PUBKEY_RESPONSE missing cert")

    # Pin the subject so a malicious server cannot swap one user's cert
    # for another's even if both are validly CA-signed.
    if not verify_certificate(cert, bytes(ca_pubkey_pem), expected_subject=username):
        raise AuthError("recipient cert verification failed")
    return cert


__all__ = ["fetch_peer_cert"]
