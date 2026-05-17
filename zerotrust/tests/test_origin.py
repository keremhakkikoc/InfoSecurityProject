"""Tests for ``common.origin`` — sign / verify of the §7.6 origin struct.

Covers issue #18 acceptance criteria:
* sign + verify happy path,
* tamper any one of the 7 fields → False (parametrised),
* tamper signature byte → False,
* dict key reordering does NOT change the signature (canonical JSON sorts).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.canonical import canonical_json
from zerotrust.common.origin import (
    _build_canonical,
    sign_origin_struct,
    verify_origin_struct,
)


CA_PASSWORD = b"ca-test-password"
ALICE_PASSWORD = b"alice-test-password"
BOB_PASSWORD = b"bob-test-password"


@dataclass
class _UserKeys:
    priv_pem: bytes
    pub_pem: bytes


def _hex_digest(label: bytes) -> str:
    """Deterministic hex string for test inputs."""
    return hashlib.sha256(label).hexdigest()


def _make_user(subject: str, password: bytes, ca_priv: bytes, ca_pub: bytes):
    priv, pub = cp.generate_rsa_keypair(password)
    cert = cert_mod.issue_certificate(subject, pub, ca_priv, CA_PASSWORD)
    assert cert_mod.verify_certificate(cert, ca_pub) is True
    return _UserKeys(priv_pem=priv, pub_pem=pub), cert


@pytest.fixture(scope="module")
def ca_keys():
    return cp.generate_rsa_keypair(CA_PASSWORD)


@pytest.fixture(scope="module")
def alice(ca_keys):
    ca_priv, ca_pub = ca_keys
    return _make_user("alice", ALICE_PASSWORD, ca_priv, ca_pub)


@pytest.fixture(scope="module")
def bob(ca_keys):
    ca_priv, ca_pub = ca_keys
    return _make_user("bob", BOB_PASSWORD, ca_priv, ca_pub)


@pytest.fixture
def baseline():
    now = int(time.time())
    return {
        "sender": "alice",
        "recipient": "bob",
        "file_id": "file-1",
        "ciphertext_sha256": _hex_digest(b"ciphertext-bytes"),
        "wrapped_key_sha256": _hex_digest(b"wrapped-key-bytes"),
        "timestamp": now,
        "expiration": now + 3600,
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_sign_verify_roundtrip(alice, baseline):
    alice_keys, alice_cert = alice
    sig = sign_origin_struct(alice_keys.priv_pem, ALICE_PASSWORD, **baseline)
    assert verify_origin_struct(alice_cert, sig, **baseline) is True


# ---------------------------------------------------------------------------
# Tamper every field
# ---------------------------------------------------------------------------

_STR_FIELDS = (
    "sender",
    "recipient",
    "file_id",
    "ciphertext_sha256",
    "wrapped_key_sha256",
)
_INT_FIELDS = ("timestamp", "expiration")


@pytest.mark.parametrize("field", _STR_FIELDS)
def test_tamper_str_field_invalidates(alice, baseline, field):
    alice_keys, alice_cert = alice
    sig = sign_origin_struct(alice_keys.priv_pem, ALICE_PASSWORD, **baseline)

    tampered = baseline.copy()
    tampered[field] = "tampered"

    assert verify_origin_struct(alice_cert, sig, **tampered) is False


@pytest.mark.parametrize("field", _INT_FIELDS)
def test_tamper_int_field_invalidates(alice, baseline, field):
    alice_keys, alice_cert = alice
    sig = sign_origin_struct(alice_keys.priv_pem, ALICE_PASSWORD, **baseline)

    tampered = baseline.copy()
    tampered[field] = baseline[field] + 1

    assert verify_origin_struct(alice_cert, sig, **tampered) is False


# ---------------------------------------------------------------------------
# Tamper signature
# ---------------------------------------------------------------------------

def test_tamper_signature_byte_invalidates(alice, baseline):
    alice_keys, alice_cert = alice
    sig = sign_origin_struct(alice_keys.priv_pem, ALICE_PASSWORD, **baseline)

    flipped = bytearray(sig)
    flipped[0] ^= 0x01

    assert verify_origin_struct(alice_cert, bytes(flipped), **baseline) is False


# ---------------------------------------------------------------------------
# Wrong signer's cert
# ---------------------------------------------------------------------------

def test_verify_with_wrong_cert_fails(alice, bob, baseline):
    alice_keys, _ = alice
    _, bob_cert = bob
    sig = sign_origin_struct(alice_keys.priv_pem, ALICE_PASSWORD, **baseline)

    assert verify_origin_struct(bob_cert, sig, **baseline) is False


# ---------------------------------------------------------------------------
# Canonicalisation invariants
# ---------------------------------------------------------------------------

def test_field_order_does_not_affect_canonical_bytes(baseline):
    """canonical_json sorts keys, so dict literal order must not matter."""
    forward = _build_canonical(**baseline)

    reordered = {k: baseline[k] for k in reversed(list(baseline))}
    backward = _build_canonical(**reordered)

    assert forward == backward


def test_canonical_uses_sorted_keys_and_compact_separators(baseline):
    """Sanity check the §7.6 contract: sort_keys=True, no whitespace."""
    canonical = _build_canonical(**baseline)
    text = canonical.decode("utf-8")

    # Keys appear in lexicographic order.
    field_positions = {
        f: text.index(f'"{f}"') for f in (
            "ciphertext_sha256", "expiration", "file_id", "recipient",
            "sender", "timestamp", "wrapped_key_sha256",
        )
    }
    sorted_positions = sorted(field_positions.values())
    assert list(field_positions.values()) == sorted_positions

    # No whitespace in separators.
    assert ", " not in text
    assert ": " not in text


def test_malformed_cert_returns_false(alice, baseline):
    alice_keys, _ = alice
    sig = sign_origin_struct(alice_keys.priv_pem, ALICE_PASSWORD, **baseline)

    # Missing public_key_pem entirely.
    assert verify_origin_struct({}, sig, **baseline) is False
    # Non-string PEM value.
    assert verify_origin_struct({"public_key_pem": 42}, sig, **baseline) is False
    # Wrong type for cert (not a dict).
    assert verify_origin_struct(None, sig, **baseline) is False


def test_unused_canonical_helper_matches_inline(baseline):
    """Defends against drift in _build_canonical vs the issue spec."""
    expected = canonical_json(
        {
            "sender": baseline["sender"],
            "recipient": baseline["recipient"],
            "file_id": baseline["file_id"],
            "ciphertext_sha256": baseline["ciphertext_sha256"],
            "wrapped_key_sha256": baseline["wrapped_key_sha256"],
            "timestamp": baseline["timestamp"],
            "expiration": baseline["expiration"],
        }
    )
    assert _build_canonical(**baseline) == expected
