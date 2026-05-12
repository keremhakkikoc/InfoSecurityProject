"""Client upload flow — Phase 2 issues #10, #11a, #11b, #12.

Encrypts the file with a fresh AES-GCM key, wraps the key under the
recipient's public key (RSA-OAEP), signs the canonical origin struct
(ARCHITECTURE.md §7.6), and sends ``UPLOAD_REQUEST``.
"""

from __future__ import annotations


def upload_file(session: dict, recipient_username: str, file_path: str,
                expiration_seconds: int) -> dict:
    """Return the server's ``UPLOAD_ACK`` payload on success.

    ``session`` is the dict returned by ``perform_client_handshake``.
    """
    raise NotImplementedError("client.upload.upload_file — Phase 2 issue #12")
