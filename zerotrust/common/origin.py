"""Sender origin signatures for encrypted file packages.

ARCHITECTURE.md §7.6 freezes the exact canonical JSON struct signed by the
sender. Keep this module as the single place that constructs those bytes so
upload, server verification, and recipient verification cannot drift.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json
from .crypto_primitives import rsa_sign, rsa_verify
from .exceptions import CryptoError


def _build_canonical(
    *,
    sender: str,
    recipient: str,
    file_id: str,
    ciphertext_sha256: str,
    wrapped_key_sha256: str,
    timestamp: int,
    expiration: int,
) -> bytes:
    """Build the frozen ARCHITECTURE.md §7.6 file-origin struct."""
    return canonical_json(
        {
            "sender": sender,
            "recipient": recipient,
            "file_id": file_id,
            "ciphertext_sha256": ciphertext_sha256,
            "wrapped_key_sha256": wrapped_key_sha256,
            "timestamp": timestamp,
            "expiration": expiration,
        }
    )


def sign_origin_struct(
    sender_priv: bytes,
    password: bytes,
    *,
    sender: str,
    recipient: str,
    file_id: str,
    ciphertext_sha256: str,
    wrapped_key_sha256: str,
    timestamp: int,
    expiration: int,
) -> bytes:
    """Return an RSA-PSS signature over the sender-origin canonical struct."""
    canonical = _build_canonical(
        sender=sender,
        recipient=recipient,
        file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp,
        expiration=expiration,
    )
    return rsa_sign(sender_priv, password, canonical)


def verify_origin_struct(
    sender_cert: dict[str, Any],
    signature: bytes,
    *,
    sender: str,
    recipient: str,
    file_id: str,
    ciphertext_sha256: str,
    wrapped_key_sha256: str,
    timestamp: int,
    expiration: int,
) -> bool:
    """Return True iff *signature* matches the frozen origin struct.

    Verification is fail-closed: malformed certificates, non-PEM public keys,
    and invalid signatures all produce ``False`` for callers to reject.
    """
    try:
        public_key_pem = sender_cert["public_key_pem"].encode("ascii")
        canonical = _build_canonical(
            sender=sender,
            recipient=recipient,
            file_id=file_id,
            ciphertext_sha256=ciphertext_sha256,
            wrapped_key_sha256=wrapped_key_sha256,
            timestamp=timestamp,
            expiration=expiration,
        )
        return rsa_verify(public_key_pem, canonical, signature)
    except (AttributeError, KeyError, TypeError, UnicodeEncodeError, CryptoError):
        return False


__all__ = ["sign_origin_struct", "verify_origin_struct"]
