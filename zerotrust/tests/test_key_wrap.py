"""Tests for recipient-certificate based AES key wrapping."""

from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

from zerotrust.ca.cert import issue_certificate
from zerotrust.common.crypto_primitives import generate_rsa_keypair
from zerotrust.common.exceptions import CryptoError
from zerotrust.common.key_wrap import unwrap_aes_key, wrap_aes_key_for


CA_PASSWORD = b"ca-password"
ALICE_PASSWORD = b"alice-password"
BOB_PASSWORD = b"bob-password"


@dataclass(frozen=True)
class KeyPair:
    priv_pem: bytes
    pub_pem: bytes


@pytest.fixture(scope="module")
def ca_keys() -> KeyPair:
    priv_pem, pub_pem = generate_rsa_keypair(CA_PASSWORD)
    return KeyPair(priv_pem=priv_pem, pub_pem=pub_pem)


@pytest.fixture(scope="module")
def alice_keys() -> KeyPair:
    priv_pem, pub_pem = generate_rsa_keypair(ALICE_PASSWORD)
    return KeyPair(priv_pem=priv_pem, pub_pem=pub_pem)


@pytest.fixture(scope="module")
def bob_keys() -> KeyPair:
    priv_pem, pub_pem = generate_rsa_keypair(BOB_PASSWORD)
    return KeyPair(priv_pem=priv_pem, pub_pem=pub_pem)


@pytest.fixture(scope="module")
def bob_cert(ca_keys: KeyPair, bob_keys: KeyPair) -> dict:
    return issue_certificate(
        "bob",
        bob_keys.pub_pem,
        ca_keys.priv_pem,
        CA_PASSWORD,
    )


def test_wrap_unwrap_roundtrip(bob_keys: KeyPair, bob_cert: dict):
    aes_key = os.urandom(32)
    wrapped = wrap_aes_key_for(bob_cert, aes_key)

    assert unwrap_aes_key(bob_keys.priv_pem, BOB_PASSWORD, wrapped) == aes_key


def test_unwrap_with_wrong_key_fails(bob_cert: dict, alice_keys: KeyPair):
    aes_key = os.urandom(32)
    wrapped = wrap_aes_key_for(bob_cert, aes_key)

    with pytest.raises(CryptoError):
        unwrap_aes_key(alice_keys.priv_pem, ALICE_PASSWORD, wrapped)


def test_unwrap_tampered_wrapped_key_fails(bob_keys: KeyPair, bob_cert: dict):
    aes_key = os.urandom(32)
    wrapped = bytearray(wrap_aes_key_for(bob_cert, aes_key))
    wrapped[0] ^= 0x01

    with pytest.raises(CryptoError):
        unwrap_aes_key(bob_keys.priv_pem, BOB_PASSWORD, bytes(wrapped))


@pytest.mark.parametrize("bad_key", [b"", b"\x00" * 16, b"\x00" * 31, b"\x00" * 33])
def test_wrap_rejects_non_32_byte_aes_key(bob_cert: dict, bad_key: bytes):
    with pytest.raises(ValueError, match="aes_key must be 32 bytes"):
        wrap_aes_key_for(bob_cert, bad_key)
