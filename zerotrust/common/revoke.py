"""Sender revocation signatures (issue #24 / bonus).

The bonus feature lets the sender recall a still-pending upload before
the recipient downloads it. To prove that the revoke really came from
the original sender — not from a curious server or an attacker who got
hold of a session — the request carries an RSA-PSS signature over a
frozen canonical struct:

    {"action": "revoke", "file_id": ..., "sender": ..., "timestamp": ...}

ARCHITECTURE.md §11 lists revocation as a bonus feature, and §8 lists
the file-lifecycle states (pending → revoked). The signature MUST be
verified server-side per the issue's pitfalls — having an authenticated
session is *not* enough; the per-request signature proves the request
itself wasn't forged inside an authenticated session by a buggy client.

Mirrors :mod:`zerotrust.common.origin` so upload (#19) and revoke (#24)
keep the same shape and so all canonical-JSON construction lives behind
the same chokepoint (no inline ``json.dumps`` at call sites — that's the
pitfall called out in the issue).
"""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json
from .crypto_primitives import rsa_sign, rsa_verify
from .exceptions import CryptoError

REVOKE_ACTION = "revoke"


def _build_canonical(
    *,
    sender: str,
    file_id: str,
    timestamp: int,
) -> bytes:
    """Build the frozen revoke canonical struct.

    Field order in the dict literal is irrelevant — ``canonical_json``
    sorts the keys — but the field NAMES are part of the wire contract
    and must not be renamed without bumping ARCHITECTURE.md §8 and every
    call site at once.

    The ``action`` field exists so a future "ack"-style signed request
    over the same envelope shape cannot be replayed as a revoke (and
    vice-versa): the signed bytes always start with ``"action":"revoke"``.
    """
    return canonical_json(
        {
            "action": REVOKE_ACTION,
            "file_id": file_id,
            "sender": sender,
            "timestamp": timestamp,
        }
    )


def sign_revoke_struct(
    sender_priv: bytes,
    password: bytes,
    *,
    sender: str,
    file_id: str,
    timestamp: int,
) -> bytes:
    """Return an RSA-PSS signature over the frozen revoke canonical struct.

    All binding fields are keyword-only — a positional reorder of
    ``sender`` / ``file_id`` would otherwise silently produce a valid-
    but-wrong signature, mirroring the same defence in
    :func:`zerotrust.common.origin.sign_origin_struct`.
    """
    canonical = _build_canonical(
        sender=sender, file_id=file_id, timestamp=timestamp,
    )
    return rsa_sign(sender_priv, password, canonical)


def verify_revoke_struct(
    sender_cert: dict[str, Any],
    signature: bytes,
    *,
    sender: str,
    file_id: str,
    timestamp: int,
) -> bool:
    """Return ``True`` iff *signature* matches the frozen revoke struct.

    Fail-closed: any malformed cert (missing key, non-string PEM), any
    Unicode error, or any signature failure returns ``False`` rather
    than raising — so callers can drop the request via the standard
    fail-closed branch without a special-case ``try``.

    Per the issue's pitfall list, the caller is responsible for verifying
    ``sender_cert`` against the CA *first*; this function trusts the
    embedded public key.
    """
    try:
        public_key_pem = sender_cert["public_key_pem"].encode("ascii")
        canonical = _build_canonical(
            sender=sender, file_id=file_id, timestamp=timestamp,
        )
        return rsa_verify(public_key_pem, canonical, signature)
    except (AttributeError, KeyError, TypeError, UnicodeEncodeError, CryptoError):
        return False


__all__ = [
    "REVOKE_ACTION",
    "sign_revoke_struct",
    "verify_revoke_struct",
]
