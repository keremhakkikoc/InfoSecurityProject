"""Tests for ``common.key_wrap`` helpers.

Covers the four acceptance criteria from issue #17:
* wrap-unwrap round-trip preserves the 32-byte AES key bit-for-bit,
* only the intended recipient can unwrap; another keypair → CryptoError,
* tampered wrapped bytes → CryptoError,
* aes_key must be 32 bytes (ValueError otherwise — programming error).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import CryptoError
from zerotrust.common.key_wrap import unwrap_aes_key, wrap_aes_key_for


CA_PASSWORD = b"ca-test-password"
BOB_PASSWORD = b"bob-test-password"
ALICE_PASSWORD = b"alice-test-password"


@dataclass
class _UserKeys:
    priv_pem: bytes
    pub_pem: bytes


def _make_user(subject: str, password: bytes, ca_priv: bytes, ca_pub: bytes):
    priv, pub = cp.generate_rsa_keypair(password)
    cert = cert_mod.issue_certificate(subject, pub, ca_priv, CA_PASSWORD)
    assert cert_mod.verify_certificate(cert, ca_pub) is True
    return _UserKeys(priv_pem=priv, pub_pem=pub), cert


@pytest.fixture(scope="module")
def ca_keys():
    return cp.generate_rsa_keypair(CA_PASSWORD)


@pytest.fixture(scope="module")
def bob(ca_keys):
    ca_priv, ca_pub = ca_keys
    return _make_user("bob", BOB_PASSWORD, ca_priv, ca_pub)


@pytest.fixture(scope="module")
def alice(ca_keys):
    ca_priv, ca_pub = ca_keys
    return _make_user("alice", ALICE_PASSWORD, ca_priv, ca_pub)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_wrap_unwrap_roundtrip(bob):
    bob_keys, bob_cert = bob
    aes_key = os.urandom(32)

    wrapped = wrap_aes_key_for(bob_cert, aes_key)

    assert unwrap_aes_key(bob_keys.priv_pem, BOB_PASSWORD, wrapped) == aes_key


def test_wrapped_bytes_are_not_the_aes_key(bob):
    """OAEP must produce ciphertext distinct from the plaintext AES key."""
    _, bob_cert = bob
    aes_key = os.urandom(32)

    wrapped = wrap_aes_key_for(bob_cert, aes_key)

    assert wrapped != aes_key
    # RSA-2048 OAEP output is always 256 bytes regardless of plaintext size.
    assert len(wrapped) == 256


# ---------------------------------------------------------------------------
# Wrong recipient
# ---------------------------------------------------------------------------

def test_unwrap_with_wrong_key_fails(bob, alice):
    _, bob_cert = bob
    alice_keys, _ = alice
    aes_key = os.urandom(32)
    wrapped = wrap_aes_key_for(bob_cert, aes_key)

    with pytest.raises(CryptoError):
        unwrap_aes_key(alice_keys.priv_pem, ALICE_PASSWORD, wrapped)


# ---------------------------------------------------------------------------
# Tamper
# ---------------------------------------------------------------------------

def test_unwrap_rejects_tampered_wrapped(bob):
    bob_keys, bob_cert = bob
    aes_key = os.urandom(32)
    wrapped = wrap_aes_key_for(bob_cert, aes_key)

    tampered = bytearray(wrapped)
    tampered[0] ^= 0x01

    with pytest.raises(CryptoError):
        unwrap_aes_key(bob_keys.priv_pem, BOB_PASSWORD, bytes(tampered))


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_len", [0, 16, 31, 33, 64])
def test_wrap_rejects_non_32_byte_key(bob, bad_len):
    _, bob_cert = bob
    with pytest.raises(ValueError):
        wrap_aes_key_for(bob_cert, os.urandom(bad_len))


def test_unwrap_with_wrong_password_fails(bob):
    bob_keys, bob_cert = bob
    aes_key = os.urandom(32)
    wrapped = wrap_aes_key_for(bob_cert, aes_key)

    with pytest.raises(CryptoError):
        unwrap_aes_key(bob_keys.priv_pem, b"wrong-password", wrapped)
