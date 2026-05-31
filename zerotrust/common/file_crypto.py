"""File encryption helpers with architecture-defined AES-GCM AAD binding.

These wrappers exist so callers cannot accidentally encrypt a file without
binding the ciphertext to its routing context. The AAD format
``"{file_id}|{sender}|{recipient}"`` is frozen in ARCHITECTURE.md §7.7 and
prevents an attacker (or a curious server) from substituting one row's
ciphertext into another row's metadata — the GCM auth tag depends on the AAD,
so any reuse breaks decryption with ``CryptoError``.

This module must NEVER log the AES key, plaintext, or AAD with
full identifiers. Only the high-level ``CryptoError`` from the underlying
primitive is allowed to escape.
"""

from __future__ import annotations

import os

from .crypto_primitives import AES_KEY_BYTES, aes_gcm_decrypt, aes_gcm_encrypt


def _file_aad(file_id: str, sender: str, recipient: str) -> bytes:
    """Return the file AAD format frozen in ARCHITECTURE.md §7.7."""
    return f"{file_id}|{sender}|{recipient}".encode()


def encrypt_file_blob(
    plaintext: bytes,
    file_id: str,
    sender: str,
    recipient: str,
) -> tuple[bytes, bytes, bytes]:
    """Return ``(nonce, ciphertext_with_tag, aes_key)``.

    ``aes_key`` is fresh per call (32 random bytes from ``os.urandom``). The
    caller is responsible for wrapping it with the recipient's public key
    (see issue #11a / RSA-OAEP) before transmission. Never reuse the key
    across files — the (key, nonce) pair must be unique per AES-GCM.
    """
    aes_key = os.urandom(AES_KEY_BYTES)
    nonce, ciphertext = aes_gcm_encrypt(
        aes_key,
        plaintext,
        _file_aad(file_id, sender, recipient),
    )
    return nonce, ciphertext, aes_key


def decrypt_file_blob(
    aes_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    file_id: str,
    sender: str,
    recipient: str,
) -> bytes:
    """Return plaintext.

    Raises :class:`zerotrust.common.exceptions.CryptoError` on any AAD,
    ciphertext, or key mismatch — the underlying ``aes_gcm_decrypt`` surfaces
    all three failure modes through the same exception so the caller can
    fail closed without leaking which check tripped.
    """
    return aes_gcm_decrypt(
        aes_key,
        nonce,
        ciphertext,
        _file_aad(file_id, sender, recipient),
    )
