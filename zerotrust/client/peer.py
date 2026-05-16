"""Client-side public-key directory lookup for recipients."""

from __future__ import annotations

from typing import Any

from ..ca.cert import verify_certificate
from ..common.exceptions import AuthError, ProtocolError
from ..common.protocol import make_envelope, recv_message, send_message, validate_envelope


def fetch_peer_cert(session: dict[str, Any], username: str) -> dict[str, Any]:
    """Fetch and locally verify ``username``'s CA-signed certificate."""
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
    if not verify_certificate(cert, bytes(ca_pubkey_pem), expected_subject=username):
        raise AuthError("recipient cert verification failed")
    return cert
