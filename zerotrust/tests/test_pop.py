"""Tests for the transcript hash + Proof-of-Possession sign/verify flow.

Covers ARCHITECTURE.md §7.4 (mutual PoP). The tests never log secrets and
never raise on attacker input. Implements every Acceptance Criterion and
Required Test from M2 issue #7.

The PoP itself is not a new function — it's the existing
``rsa_sign`` / ``rsa_verify`` primitives **applied to** the canonical
transcript hash. So these tests double as end-to-end PoP coverage.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.transcript import (
    NONCE_BYTES,
    TRANSCRIPT_DIGEST_BYTES,
    build_transcript_hash,
)


PASSWORD = b"pop-test-password"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ca_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture
def client_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture
def server_keys():
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture
def attacker_keys():
    """A separate keypair simulating an adversary who has stolen the
    client's cert (public) but not the matching private key."""
    return cp.generate_rsa_keypair(PASSWORD)


@pytest.fixture
def client_cert(ca_keys, client_keys):
    ca_priv, _ = ca_keys
    _, client_pub = client_keys
    return cert_mod.issue_certificate("alice", client_pub, ca_priv, PASSWORD)


@pytest.fixture
def server_cert(ca_keys, server_keys):
    ca_priv, _ = ca_keys
    _, server_pub = server_keys
    return cert_mod.issue_certificate("server-01", server_pub, ca_priv, PASSWORD)


@pytest.fixture
def fresh_handshake():
    """Return a fresh (nonce_c, nonce_s, pre_master_ct) triple."""
    return os.urandom(NONCE_BYTES), os.urandom(NONCE_BYTES), os.urandom(256)


# ===========================================================================
# Section 1: transcript hash helper
# ===========================================================================

def test_transcript_hash_is_32_bytes(fresh_handshake):
    """The transcript digest is always SHA-256 wide (32 bytes)."""
    nc, ns, pmct = fresh_handshake
    h = build_transcript_hash(nc, ns, pmct)
    assert len(h) == TRANSCRIPT_DIGEST_BYTES
    assert isinstance(h, bytes)


def test_transcript_hash_deterministic(fresh_handshake):
    """Same inputs → same output, bit for bit."""
    nc, ns, pmct = fresh_handshake
    assert build_transcript_hash(nc, ns, pmct) == build_transcript_hash(nc, ns, pmct)


def test_transcript_hash_changes_with_nonce_c(fresh_handshake):
    """A different client nonce yields a different digest."""
    nc, ns, pmct = fresh_handshake
    other_nc = os.urandom(NONCE_BYTES)
    assert build_transcript_hash(nc, ns, pmct) != build_transcript_hash(other_nc, ns, pmct)


def test_transcript_hash_changes_with_nonce_s(fresh_handshake):
    """A different server nonce yields a different digest."""
    nc, ns, pmct = fresh_handshake
    other_ns = os.urandom(NONCE_BYTES)
    assert build_transcript_hash(nc, ns, pmct) != build_transcript_hash(nc, other_ns, pmct)


def test_transcript_hash_changes_with_pre_master_ct(fresh_handshake):
    """A different pre-master ciphertext yields a different digest.

    This is the critical anti-replay property: an attacker who replays
    a captured ``nonce_c`` and ``nonce_s`` but injects a fresh OAEP
    ciphertext gets a totally different transcript hash.
    """
    nc, ns, pmct = fresh_handshake
    other_pmct = os.urandom(256)
    assert build_transcript_hash(nc, ns, pmct) != build_transcript_hash(nc, ns, other_pmct)


def test_transcript_hash_concatenation_order_matters():
    """Swapping nonce_c and nonce_s yields a different digest.

    Guards against an implementation bug where the two ends happen to
    concatenate in opposite orders and silently agree on the wrong hash
    (which would still verify against itself but defeat the security goal).
    """
    a = b"A" * NONCE_BYTES
    b = b"B" * NONCE_BYTES
    pmct = b"\x00" * 256
    assert build_transcript_hash(a, b, pmct) != build_transcript_hash(b, a, pmct)


def test_transcript_hash_matches_reference_implementation(fresh_handshake):
    """Cross-check against a plain hashlib call.

    Defends against future refactors that accidentally introduce a
    different hash function or change the concatenation rule.
    """
    nc, ns, pmct = fresh_handshake
    expected = hashlib.sha256(nc + ns + pmct).digest()
    assert build_transcript_hash(nc, ns, pmct) == expected


def test_transcript_hash_rejects_wrong_length_nonce_c(fresh_handshake):
    _, ns, pmct = fresh_handshake
    with pytest.raises(ValueError, match="nonce_c"):
        build_transcript_hash(b"\x00" * 8, ns, pmct)


def test_transcript_hash_rejects_wrong_length_nonce_s(fresh_handshake):
    nc, _, pmct = fresh_handshake
    with pytest.raises(ValueError, match="nonce_s"):
        build_transcript_hash(nc, b"\x00" * 32, pmct)


def test_transcript_hash_rejects_empty_pre_master_ct(fresh_handshake):
    nc, ns, _ = fresh_handshake
    with pytest.raises(ValueError, match="pre_master_ct"):
        build_transcript_hash(nc, ns, b"")


def test_transcript_hash_rejects_non_bytes_input(fresh_handshake):
    nc, ns, pmct = fresh_handshake
    with pytest.raises(ValueError, match="must be bytes"):
        build_transcript_hash("not-bytes", ns, pmct)  # type: ignore[arg-type]


def test_transcript_hash_accepts_bytearray(fresh_handshake):
    """bytearray is functionally the same as bytes; both must be accepted."""
    nc, ns, pmct = fresh_handshake
    h_bytes = build_transcript_hash(nc, ns, pmct)
    h_ba = build_transcript_hash(bytearray(nc), bytearray(ns), bytearray(pmct))
    assert h_bytes == h_ba


# ===========================================================================
# Section 2: PoP end-to-end — client signs, server verifies
# ===========================================================================

def _client_signs_pop(client_priv_pem: bytes, transcript: bytes) -> bytes:
    """Helper: client's side of the PoP — sign the transcript."""
    return cp.rsa_sign(client_priv_pem, PASSWORD, transcript)


def _server_verifies_pop(client_cert: dict, transcript: bytes, signature: bytes) -> bool:
    """Helper: server's side of the PoP — extract pubkey from cert and verify."""
    pubkey_pem = client_cert["public_key_pem"].encode("ascii")
    return cp.rsa_verify(pubkey_pem, transcript, signature)


def test_pop_happy_path_client_to_server(client_keys, client_cert, fresh_handshake):
    """AC 1a: Correct PoP signature verifies on the server side."""
    client_priv, _ = client_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = _client_signs_pop(client_priv, transcript)
    assert _server_verifies_pop(client_cert, transcript, sig) is True


def test_pop_happy_path_server_to_client(server_keys, server_cert, fresh_handshake):
    """AC 1b: Correct PoP signature verifies on the client side.

    The server signs the same transcript in SESSION_OK; the client must
    verify before considering the session authenticated.
    """
    server_priv, _ = server_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = cp.rsa_sign(server_priv, PASSWORD, transcript)
    server_pubkey = server_cert["public_key_pem"].encode("ascii")
    assert cp.rsa_verify(server_pubkey, transcript, sig) is True


# ===========================================================================
# Section 3: tampering — every field in the transcript binds the signature
# ===========================================================================

def test_pop_rejects_tampered_nonce_c(client_keys, client_cert, fresh_handshake):
    """AC 2a: Flipping a byte in nonce_c after signing → verify False."""
    client_priv, _ = client_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = _client_signs_pop(client_priv, transcript)

    tampered_nc = bytearray(nc)
    tampered_nc[0] ^= 0x01
    tampered_transcript = build_transcript_hash(bytes(tampered_nc), ns, pmct)
    assert _server_verifies_pop(client_cert, tampered_transcript, sig) is False


def test_pop_rejects_tampered_nonce_s(client_keys, client_cert, fresh_handshake):
    """AC 2b: Flipping a byte in nonce_s after signing → verify False."""
    client_priv, _ = client_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = _client_signs_pop(client_priv, transcript)

    tampered_ns = bytearray(ns)
    tampered_ns[-1] ^= 0x80
    tampered_transcript = build_transcript_hash(nc, bytes(tampered_ns), pmct)
    assert _server_verifies_pop(client_cert, tampered_transcript, sig) is False


def test_pop_rejects_tampered_pre_master_ct(client_keys, client_cert, fresh_handshake):
    """AC 2c: Flipping a byte in pre_master_ct after signing → verify False.

    This is the most important anti-replay property: an attacker who
    captures (nc, ns, sig) and tries to inject a different pre_master_ct
    cannot reuse the signature.
    """
    client_priv, _ = client_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = _client_signs_pop(client_priv, transcript)

    tampered_pmct = bytearray(pmct)
    tampered_pmct[100] ^= 0xFF
    tampered_transcript = build_transcript_hash(nc, ns, bytes(tampered_pmct))
    assert _server_verifies_pop(client_cert, tampered_transcript, sig) is False


# ===========================================================================
# Section 4: signature tampering
# ===========================================================================

def test_pop_rejects_one_byte_signature_flip(client_keys, client_cert, fresh_handshake):
    """AC 3: A single bit flip in the signature → verify False."""
    client_priv, _ = client_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = bytearray(_client_signs_pop(client_priv, transcript))
    sig[0] ^= 0x01
    assert _server_verifies_pop(client_cert, transcript, bytes(sig)) is False


def test_pop_rejects_truncated_signature(client_keys, client_cert, fresh_handshake):
    """A truncated signature must be rejected without raising."""
    client_priv, _ = client_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = _client_signs_pop(client_priv, transcript)
    assert _server_verifies_pop(client_cert, transcript, sig[:-1]) is False


def test_pop_rejects_zero_signature(client_cert, fresh_handshake):
    """An all-zeros signature must be rejected."""
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    bogus = b"\x00" * 256
    assert _server_verifies_pop(client_cert, transcript, bogus) is False


def test_pop_rejects_random_garbage_signature(client_cert, fresh_handshake):
    """Random bytes of the right length must be rejected."""
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    garbage = os.urandom(256)
    assert _server_verifies_pop(client_cert, transcript, garbage) is False


# ===========================================================================
# Section 5: identity substitution — the headline attack PoP defends against
# ===========================================================================

def test_pop_rejects_attacker_with_stolen_cert(
    client_cert, attacker_keys, fresh_handshake
):
    """AC 4: Classic identity substitution.

    An attacker has captured Alice's cert (public, freely available) but
    does NOT have Alice's private key. They generate their own keypair
    and try to authenticate as Alice by:

      1. Presenting Alice's cert (so the cert chain verifies).
      2. Signing the transcript with their OWN private key.

    The server must reject this in step 2: ``rsa_verify`` uses the pubkey
    embedded in the (real) cert, which does NOT match the attacker's key.
    """
    attacker_priv, _ = attacker_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    forged_sig = cp.rsa_sign(attacker_priv, PASSWORD, transcript)
    # Attacker waves Alice's cert around but signed with their own key.
    assert _server_verifies_pop(client_cert, transcript, forged_sig) is False


def test_pop_rejects_signer_for_wrong_session(client_keys, client_cert):
    """A legitimate Alice signature for ONE session must NOT verify
    against ANOTHER session's transcript.

    (Defeats a replay where an attacker captures a signed transcript
    from a past session and presents it for a fresh handshake.)
    """
    client_priv, _ = client_keys
    # Session A: client signs.
    nc_a, ns_a, pmct_a = (os.urandom(NONCE_BYTES), os.urandom(NONCE_BYTES),
                          os.urandom(256))
    transcript_a = build_transcript_hash(nc_a, ns_a, pmct_a)
    sig_a = _client_signs_pop(client_priv, transcript_a)

    # Session B: completely fresh nonces, different pre-master.
    nc_b, ns_b, pmct_b = (os.urandom(NONCE_BYTES), os.urandom(NONCE_BYTES),
                          os.urandom(256))
    transcript_b = build_transcript_hash(nc_b, ns_b, pmct_b)

    # Replay sig_a into session B → must fail.
    assert _server_verifies_pop(client_cert, transcript_b, sig_a) is False


# ===========================================================================
# Section 6: fail-closed behaviour — verify never raises on attacker input
# ===========================================================================

def test_pop_verify_returns_false_on_garbage_signature(client_cert, fresh_handshake):
    """AC 5: rsa_verify must NEVER raise on bad signature bytes —
    only return False. Caller code uses it directly in fail-closed
    branches; an unhandled exception would crash the server thread.
    """
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    # Multiple shapes of garbage — none must raise.
    for bad in (b"", b"\x00", os.urandom(1), os.urandom(255), os.urandom(513)):
        result = _server_verifies_pop(client_cert, transcript, bad)
        assert result is False, f"verify raised or returned True on {len(bad)}-byte garbage"


def test_pop_verify_with_swapped_cert_does_not_raise(
    client_keys, server_cert, fresh_handshake
):
    """If the server pulls the WRONG cert from its directory by mistake
    (e.g. mixed up subjects), verify must return False, not raise.

    This is what makes the server thread resilient — a bug in the
    directory lookup cannot crash the connection handler.
    """
    client_priv, _ = client_keys
    nc, ns, pmct = fresh_handshake
    transcript = build_transcript_hash(nc, ns, pmct)
    sig = _client_signs_pop(client_priv, transcript)
    # Use the SERVER's cert to verify a CLIENT signature — wrong pubkey,
    # but the function must still fail-closed cleanly.
    assert _server_verifies_pop(server_cert, transcript, sig) is False
