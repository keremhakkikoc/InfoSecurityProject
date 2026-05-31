"""Per-file AES key wrapping helpers.

End-to-end means the server cannot read the file: the per-file AES-256 key is
wrapped under the **recipient's** public key with RSA-OAEP, so only the
recipient — who holds the matching private key — can unwrap and decrypt.

The recipient certificate is the contract here, not the raw PEM: callers pass
a CA-verified certificate dict, and this module extracts the public key for
wrapping per ARCHITECTURE.md §2 and §3.

Wrapped bytes must NEVER be exported via ``str()`` — base64
encode (``base64.b64encode(wrapped).decode("ascii")``) before placing in any
JSON payload.
"""

from __future__ import annotations

from .crypto_primitives import AES_KEY_BYTES, rsa_oaep_decrypt, rsa_oaep_encrypt


def wrap_aes_key_for(recipient_cert: dict, aes_key: bytes) -> bytes:
    """Wrap a 32-byte AES key under the recipient's RSA pubkey via OAEP.

    ``recipient_cert`` is the CA-verified certificate dict (see
    :func:`zerotrust.ca.cert.verify_certificate`). The caller MUST have
    verified the certificate before calling — this helper does not re-verify.

    Raises ``ValueError`` if ``aes_key`` is not exactly 32 bytes, which is a
    programming error (AES-256 requirement, see ARCHITECTURE.md §2).
    """
    if len(aes_key) != AES_KEY_BYTES:
        raise ValueError(f"aes_key must be {AES_KEY_BYTES} bytes")
    pub_pem = recipient_cert["public_key_pem"].encode("ascii")
    return rsa_oaep_encrypt(pub_pem, aes_key)


def unwrap_aes_key(my_priv_pem: bytes, my_password: bytes, wrapped: bytes) -> bytes:
    """Inverse of :func:`wrap_aes_key_for`.

    Raises :class:`zerotrust.common.exceptions.CryptoError` on any failure
    (wrong key, tampered ciphertext, padding error). Surfaces a single error
    type so call sites can fail closed without leaking which check tripped.
    """
    return rsa_oaep_decrypt(my_priv_pem, my_password, wrapped)
