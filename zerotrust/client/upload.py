"""Client upload flow — Phase 2 issues #10, #11a, #11b, #12.

Encrypts the file with a fresh AES-GCM key, wraps the key under the
recipient's public key (RSA-OAEP), signs the canonical origin struct
(ARCHITECTURE.md §7.6), and sends ``UPLOAD_REQUEST``.
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from pathlib import Path
from typing import Any

from ..common.exceptions import ProtocolError
from ..common.file_crypto import encrypt_file_blob
from ..common.key_wrap import wrap_aes_key_for
from ..common.origin import sign_origin_struct
from ..common.protocol import (
    MAX_MESSAGE_BYTES,
    make_envelope,
    recv_message,
    send_message,
    validate_envelope,
)
from .peer import fetch_peer_cert


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def upload_file(
    session: dict[str, Any],
    recipient_username: str,
    file_path: str,
    expiration_seconds: int = 7 * 86400,
) -> dict[str, Any]:
    """Return the server's ``UPLOAD_ACK`` payload on success.

    ``session`` is the dict returned by ``perform_client_handshake``.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError("FILE_NOT_FOUND")
    if path.stat().st_size > MAX_MESSAGE_BYTES:
        raise ProtocolError("MESSAGE_TOO_LARGE")

    sender = session.get("username")
    sock = session.get("sock")
    sender_priv = session.get("client_priv_pem")
    sender_password = session.get("client_password")
    if not isinstance(sender, str) or sock is None:
        raise ProtocolError("live client session is required")
    if not isinstance(sender_priv, (bytes, bytearray)):
        raise ProtocolError("sender private key missing from session")
    if not isinstance(sender_password, (bytes, bytearray)):
        raise ProtocolError("sender password missing from session")

    recipient_cert = fetch_peer_cert(session, recipient_username)

    with path.open("rb") as f:
        plaintext = f.read()

    file_id = str(uuid.uuid4())
    nonce, ciphertext, aes_key = encrypt_file_blob(
        plaintext,
        file_id,
        sender=sender,
        recipient=recipient_username,
    )
    wrapped_key = wrap_aes_key_for(recipient_cert, aes_key)

    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
    timestamp = int(time.time())
    expiration = timestamp + expiration_seconds
    signature = sign_origin_struct(
        bytes(sender_priv),
        bytes(sender_password),
        sender=sender,
        recipient=recipient_username,
        file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp,
        expiration=expiration,
    )

    payload = {
        "file_id": file_id,
        "recipient": recipient_username,
        "ciphertext": _b64(ciphertext),
        "nonce": _b64(nonce),
        "wrapped_key": _b64(wrapped_key),
        "signature": _b64(signature),
        "timestamp": timestamp,
        "expiration": expiration,
    }
    send_message(sock, make_envelope("UPLOAD_REQUEST", payload))

    reply = validate_envelope(recv_message(sock))
    if reply["type"] == "ERROR":
        code = reply["payload"].get("code", "ERROR")
        raise ProtocolError(str(code))
    if reply["type"] != "UPLOAD_ACK":
        raise ProtocolError(f"expected UPLOAD_ACK, got {reply['type']!r}")
    return reply["payload"]
