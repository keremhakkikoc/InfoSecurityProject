"""Per-file AES key wrapping helpers.

The recipient certificate is the contract here: callers pass a CA-verified
certificate dict, and this module extracts the public key used for RSA-OAEP
wrapping per ARCHITECTURE.md §2 and §8.
"""

from __future__ import annotations

from .crypto_primitives import AES_KEY_BYTES, rsa_oaep_decrypt, rsa_oaep_encrypt


def wrap_aes_key_for(recipient_cert: dict, aes_key: bytes) -> bytes:
    """Wrap a 32-byte AES key under the recipient's RSA pubkey via OAEP."""
    if len(aes_key) != AES_KEY_BYTES:
        raise ValueError("aes_key must be 32 bytes")
    pub_pem = recipient_cert["public_key_pem"].encode("ascii")
    return rsa_oaep_encrypt(pub_pem, aes_key)


def unwrap_aes_key(my_priv_pem: bytes, my_password: bytes, wrapped: bytes) -> bytes:
    """Inverse of wrap_aes_key_for. Raises CryptoError on any failure."""
    return rsa_oaep_decrypt(my_priv_pem, my_password, wrapped)
