"""File encryption helpers with architecture-defined AES-GCM AAD binding."""

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
    """Return (nonce, ciphertext_with_tag, aes_key).

    aes_key is fresh per call (32 random bytes). Caller is responsible for
    wrapping it with the recipient's public key before upload.
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
    """Return plaintext. Raises CryptoError on any AAD, ciphertext, or key mismatch."""
    return aes_gcm_decrypt(
        aes_key,
        nonce,
        ciphertext,
        _file_aad(file_id, sender, recipient),
    )
