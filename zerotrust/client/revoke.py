"""Client revoke flow (issue #24 / bonus).

Symmetric to :func:`zerotrust.client.upload.upload_file` — builds the
canonical revoke struct, signs it with the user's RSA-PSS key, sends
``REVOKE_REQUEST``, and surfaces the server's ``REVOKE_ACK`` payload
(or raises :class:`ProtocolError` for any ``ERROR`` reply).

The signature is over the frozen canonical struct from
:mod:`zerotrust.common.revoke` — never an inline ``json.dumps`` (that's
one of the pitfalls explicitly called out in the issue body).
"""

from __future__ import annotations

import base64
import time
from typing import Any

from ..common.exceptions import ProtocolError
from ..common.protocol import (
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from ..common.revoke import sign_revoke_struct


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def revoke_file(session: dict[str, Any], file_id: str) -> dict[str, Any]:
    """Send a signed ``REVOKE_REQUEST`` for *file_id* and return the ACK payload.

    Args:
        session: Live session dict from
            :func:`zerotrust.client.session.connected_session`.
        file_id: UUID-shaped identifier of the file to revoke.

    Returns:
        The server's ``REVOKE_ACK`` payload, e.g. ``{"file_id": ...,
        "status": "revoked"}``. The acceptance criteria call out that a
        second revoke of the same file is idempotent — the server still
        replies with a ``REVOKE_ACK`` so this function still returns the
        payload rather than raising.

    Raises:
        ProtocolError: malformed reply or any server-side ``ERROR``
            envelope (``NOT_FOUND``, ``NOT_AUTHORIZED``, ``AUTH_FAILED``,
            ``ALREADY_DOWNLOADED``, ``EXPIRED``, ``STALE`` / ``REPLAY``,
            ``MALFORMED``).
    """
    if not isinstance(file_id, str) or not file_id:
        raise ProtocolError("file_id must be a non-empty string")

    sock = session.get("sock")
    sender = session.get("username")
    sender_priv = session.get("client_priv_pem")
    sender_password = session.get("client_password")
    if sock is None or not isinstance(sender, str):
        raise ProtocolError("live client session is required")
    if not isinstance(sender_priv, (bytes, bytearray)):
        raise ProtocolError("sender private key missing from session")
    if not isinstance(sender_password, (bytes, bytearray)):
        raise ProtocolError("sender password missing from session")

    timestamp = int(time.time())
    signature = sign_revoke_struct(
        bytes(sender_priv),
        bytes(sender_password),
        sender=sender,
        file_id=file_id,
        timestamp=timestamp,
    )

    payload = {
        "file_id": file_id,
        "timestamp": timestamp,
        "signature": _b64(signature),
    }
    send_message(sock, make_envelope("REVOKE_REQUEST", payload))

    reply = validate_envelope(recv_message(sock))
    if reply["type"] == "ERROR":
        code = reply["payload"].get("code", "ERROR")
        raise ProtocolError(str(code))
    if reply["type"] != "REVOKE_ACK":
        raise ProtocolError(f"expected REVOKE_ACK, got {reply['type']!r}")
    return reply["payload"]


__all__ = ["revoke_file"]
