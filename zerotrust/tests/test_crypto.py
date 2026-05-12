"""Tests for common.crypto_primitives.

Each primitive has a happy-path test and at least one negative-path test
covering tampering / wrong key / wrong AAD per AI.md §5.42.
"""

from __future__ import annotations

import os

import pytest

from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import CryptoError


PASSWORD = b"unit-test-password"


@pytest.fixture(scope="module")
def keypair():
    return cp.generate_rsa_keypair(PASSWORD)


# ---------------------------------------------------------------------------
# RSA keygen + PEM encryption
# ---------------------------------------------------------------------------

def test_generate_keypair_returns_pem(keypair):
    priv, pub = keypair
    assert priv.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_generate_rejects_empty_password():
    with pytest.raises(ValueError):
        cp.generate_rsa_keypair(b"")


def test_load_with_wrong_password_fails(keypair):
    priv, _ = keypair
    with pytest.raises(CryptoError):
        cp.rsa_sign(priv, b"wrong-password", b"hello")


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def test_sign_verify_roundtrip(keypair):
    priv, pub = keypair
    sig = cp.rsa_sign(priv, PASSWORD, b"hello world")
    assert cp.rsa_verify(pub, b"hello world", sig) is True


def test_verify_rejects_tampered_message(keypair):
    priv, pub = keypair
    sig = cp.rsa_sign(priv, PASSWORD, b"hello world")
    assert cp.rsa_verify(pub, b"hello world!", sig) is False


def test_verify_rejects_tampered_signature(keypair):
    priv, pub = keypair
    sig = bytearray(cp.rsa_sign(priv, PASSWORD, b"hi"))
    sig[0] ^= 0x01
    assert cp.rsa_verify(pub, b"hi", bytes(sig)) is False


def test_verify_rejects_signature_from_different_key(keypair):
    _, pub = keypair
    other_priv, _ = cp.generate_rsa_keypair(PASSWORD)
    sig = cp.rsa_sign(other_priv, PASSWORD, b"data")
    assert cp.rsa_verify(pub, b"data", sig) is False


# ---------------------------------------------------------------------------
# RSA-OAEP
# ---------------------------------------------------------------------------

def test_oaep_roundtrip(keypair):
    priv, pub = keypair
    pre_master = os.urandom(32)
    ct = cp.rsa_oaep_encrypt(pub, pre_master)
    assert cp.rsa_oaep_decrypt(priv, PASSWORD, ct) == pre_master


def test_oaep_decrypt_rejects_tampered_ciphertext(keypair):
    priv, pub = keypair
    ct = bytearray(cp.rsa_oaep_encrypt(pub, b"secret"))
    ct[10] ^= 0x01
    with pytest.raises(CryptoError):
        cp.rsa_oaep_decrypt(priv, PASSWORD, bytes(ct))


def test_oaep_decrypt_with_wrong_key_fails(keypair):
    _, pub = keypair
    other_priv, _ = cp.generate_rsa_keypair(PASSWORD)
    ct = cp.rsa_oaep_encrypt(pub, b"secret")
    with pytest.raises(CryptoError):
        cp.rsa_oaep_decrypt(other_priv, PASSWORD, ct)


# ---------------------------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------------------------

def test_aes_gcm_roundtrip():
    key = os.urandom(32)
    aad = b"file_id|alice|bob"
    nonce, ct = cp.aes_gcm_encrypt(key, b"hello", aad)
    assert len(nonce) == 12
    assert cp.aes_gcm_decrypt(key, nonce, ct, aad) == b"hello"


def test_aes_gcm_rejects_aad_mismatch():
    key = os.urandom(32)
    nonce, ct = cp.aes_gcm_encrypt(key, b"hello", b"aad-A")
    with pytest.raises(CryptoError):
        cp.aes_gcm_decrypt(key, nonce, ct, b"aad-B")


def test_aes_gcm_rejects_tampered_ciphertext():
    key = os.urandom(32)
    aad = b"x"
    nonce, ct = cp.aes_gcm_encrypt(key, b"hello", aad)
    ct = bytearray(ct)
    ct[0] ^= 0x01
    with pytest.raises(CryptoError):
        cp.aes_gcm_decrypt(key, nonce, bytes(ct), aad)


def test_aes_gcm_rejects_wrong_key():
    key = os.urandom(32)
    nonce, ct = cp.aes_gcm_encrypt(key, b"hello", b"aad")
    with pytest.raises(CryptoError):
        cp.aes_gcm_decrypt(os.urandom(32), nonce, ct, b"aad")


def test_aes_gcm_rejects_bad_key_length():
    with pytest.raises(ValueError):
        cp.aes_gcm_encrypt(b"\x00" * 16, b"hi", b"")


def test_aes_gcm_nonces_are_fresh():
    key = os.urandom(32)
    nonces = {cp.aes_gcm_encrypt(key, b"x", b"y")[0] for _ in range(50)}
    assert len(nonces) == 50  # uniqueness with overwhelming probability


# ---------------------------------------------------------------------------
# HKDF
# ---------------------------------------------------------------------------

def test_hkdf_deterministic_with_same_inputs():
    okm1 = cp.hkdf_derive(b"ikm", b"salt", b"info", 64)
    okm2 = cp.hkdf_derive(b"ikm", b"salt", b"info", 64)
    assert okm1 == okm2
    assert len(okm1) == 64


def test_hkdf_distinct_with_different_salts():
    okm1 = cp.hkdf_derive(b"ikm", b"salt-A", b"info", 32)
    okm2 = cp.hkdf_derive(b"ikm", b"salt-B", b"info", 32)
    assert okm1 != okm2


def test_hkdf_rejects_zero_length():
    with pytest.raises(ValueError):
        cp.hkdf_derive(b"ikm", b"salt", b"info", 0)
