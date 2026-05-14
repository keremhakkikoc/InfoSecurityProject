"""Handshake transcript hash builder per ARCHITECTURE.md §7.4.

The transcript hash binds **both** nonces AND the OAEP-encrypted pre-master
into a single 32-byte digest. Each side of the handshake signs this digest
to prove it holds the private key matching the cert it presented (mutual
proof-of-possession).

Why bind all three?
* Without ``pre_master_ct``: an attacker can swap pre-masters across
  sessions and reuse a captured signature.
* Without ``nonce_s``: a malicious server replays a captured handshake.
* Without ``nonce_c``: a malicious client replays.

Binding all three with a strong hash defeats every replay / substitution
variant within the threat model.

Why hash the **ciphertext** of the pre-master, not the plaintext?
Both sides can recompute the digest immediately after seeing the
KEY_EXCHANGE message on the wire, **before** the server has even
decrypted. This lets the server reject forged signatures without
revealing whether decryption succeeded — a useful side-channel
hardening property.
"""

from __future__ import annotations

import hashlib

# Nonces are 16 bytes (128 bits) per ARCHITECTURE.md §7.2 envelope spec.
# We enforce this length so a programming error (e.g. accidentally passing
# a base64 string instead of the decoded bytes) is caught at the boundary
# rather than silently producing a hash that the other side cannot match.
NONCE_BYTES = 16
TRANSCRIPT_DIGEST_BYTES = 32  # SHA-256 output


def build_transcript_hash(
    nonce_c: bytes,
    nonce_s: bytes,
    pre_master_ct: bytes,
) -> bytes:
    """Compute the 32-byte SHA-256 transcript hash for a handshake.

    Args:
        nonce_c: 16 random bytes from the client (sent in HELLO).
        nonce_s: 16 random bytes from the server (sent in HELLO).
        pre_master_ct: the RSA-OAEP-encrypted pre-master secret bytes
            (the exact bytes sent on the wire in KEY_EXCHANGE).

    Returns:
        32 bytes — ``SHA-256(nonce_c || nonce_s || pre_master_ct)``.

    Raises:
        ValueError: on a wrong-length nonce or on non-bytes input. These
            are programming errors at the call site, not attacker-driven
            failures, so raising is appropriate.

    The ordering ``nonce_c || nonce_s || pre_master_ct`` is FROZEN by
    ARCHITECTURE.md §7.4. Both peers MUST concatenate in this exact order
    or their hashes will differ.
    """
    for name, value in (("nonce_c", nonce_c),
                        ("nonce_s", nonce_s),
                        ("pre_master_ct", pre_master_ct)):
        if not isinstance(value, (bytes, bytearray)):
            raise ValueError(f"{name} must be bytes, got {type(value).__name__}")

    if len(nonce_c) != NONCE_BYTES:
        raise ValueError(
            f"nonce_c must be {NONCE_BYTES} bytes, got {len(nonce_c)}"
        )
    if len(nonce_s) != NONCE_BYTES:
        raise ValueError(
            f"nonce_s must be {NONCE_BYTES} bytes, got {len(nonce_s)}"
        )
    if len(pre_master_ct) == 0:
        raise ValueError("pre_master_ct must be non-empty")

    h = hashlib.sha256()
    h.update(bytes(nonce_c))
    h.update(bytes(nonce_s))
    h.update(bytes(pre_master_ct))
    return h.digest()
