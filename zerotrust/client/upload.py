"""Client upload flow — the integration point for milestone-2 issue #19.

Consumes everything upstream:

* ``encrypt_file_blob`` (#16) — AES-GCM with AAD binding
* ``wrap_aes_key_for`` (#17) — RSA-OAEP under recipient pubkey
* ``sign_origin_struct`` (#18) — RSA-PSS over canonical struct
* ``fetch_peer_cert`` (#21 via :mod:`peer`) — GET_PUBKEY round-trip

Local-only checks (``FILE_NOT_FOUND``, oversize) happen BEFORE any network
I/O so a broken invocation never reaches the server.

Per the issue's pitfalls, the AES key itself is NEVER placed in the
envelope — only ``wrapped_key`` goes on the wire — and the SHA-256 digests
are computed over the **ciphertext** / wrapped key, never the plaintext.
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


DEFAULT_EXPIRATION_SECONDS = 7 * 86400  # one week


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def upload_file(
    session: dict[str, Any],
    recipient_username: str,
    file_path: str,
    expiration_seconds: int = DEFAULT_EXPIRATION_SECONDS,
) -> dict[str, Any]:
    """Return the server's ``UPLOAD_ACK`` payload on success.

    Args:
        session: Live session dict from
            :func:`zerotrust.client.session.connected_session`.
        recipient_username: Whose pubkey to wrap the AES key under.
        file_path: Local path to the file to upload.
        expiration_seconds: Time-to-live for the upload (default 7 days).

    Raises:
        FileNotFoundError(``FILE_NOT_FOUND``): the file does not exist.
            Raised BEFORE any network call so a missing file is a pure
            local error per the issue's acceptance criteria.
        ProtocolError: oversize file, malformed reply, or any server-side
            ``ERROR`` envelope (carries the server's error code).
        AuthError: recipient cert verification failed.
    """
    path = Path(file_path)
    # Local checks first — don't hit the network for a typo.
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

    # Fetch & locally verify recipient's CA-signed cert before reading the
    # plaintext into memory — failing here means a typo'd recipient never
    # causes us to touch the file.
    recipient_cert = fetch_peer_cert(session, recipient_username)

    with path.open("rb") as f:
        plaintext = f.read()

    # Build the package.
    file_id = str(uuid.uuid4())
    nonce, ciphertext, aes_key = encrypt_file_blob(
        plaintext,
        file_id,
        sender=sender,
        recipient=recipient_username,
    )
    wrapped_key = wrap_aes_key_for(recipient_cert, aes_key)

    # Hash ciphertext (NEVER plaintext — that would leak content to the server).
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
    # NB: M2 sends the envelope as plaintext over the TCP socket. The file
    # payload itself is AES-GCM ciphertext, so the only thing exposed is
    # routing metadata. Channel encryption (c2s_key wrap) is deferred to
    # a later milestone as defence-in-depth.
    send_message(sock, make_envelope("UPLOAD_REQUEST", payload))

    reply = validate_envelope(recv_message(sock))
    if reply["type"] == "ERROR":
        code = reply["payload"].get("code", "ERROR")
        raise ProtocolError(str(code))
    if reply["type"] != "UPLOAD_ACK":
        raise ProtocolError(f"expected UPLOAD_ACK, got {reply['type']!r}")
    return reply["payload"]


__all__ = ["upload_file", "DEFAULT_EXPIRATION_SECONDS"]
