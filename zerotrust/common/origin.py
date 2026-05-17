"""Sender origin signatures for encrypted file packages.

ARCHITECTURE.md §7.6 freezes the exact canonical JSON struct signed by the
sender. Keep this module as the single place that constructs those bytes so
upload (#12), server-side verify (#13), and recipient verify (#18) cannot
drift apart — any whitespace, ordering, or field-name mismatch breaks the
RSA-PSS signature.

The struct binds **both** ``ciphertext_sha256`` and ``wrapped_key_sha256`` so
a malicious server cannot substitute either component (or just the wrapped
key) and remain undetectable.

Both hash fields are lowercase hex strings, not raw bytes — chosen for JSON
portability per AI.md §2.
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
    """Build the frozen ARCHITECTURE.md §7.6 file-origin struct.

    The dict literal order here is irrelevant — ``canonical_json`` sorts keys
    — but the field NAMES are part of the on-the-wire contract and must not
    change without updating ARCHITECTURE.md §7.6 and every call site.
    """
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
    """Return an RSA-PSS signature over the sender-origin canonical struct.

    All routing/binding fields are keyword-only to prevent accidental
    positional reorder by callers — a positional swap of ``sender`` and
    ``recipient`` would silently produce a valid-but-wrong signature.
    """
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
    """Return ``True`` iff *signature* matches the frozen origin struct.

    Fail-closed: malformed certs (missing key, non-string PEM), unicode
    errors, or any signature failure return ``False`` rather than raising,
    so callers can drop the request without a special-case ``try`` block.

    The caller is responsible for verifying ``sender_cert`` against the CA
    first — this function trusts the embedded public key.
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
