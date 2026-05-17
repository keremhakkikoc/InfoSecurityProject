"""Tests for ``common.file_crypto`` helpers.

These cover the four acceptance criteria from issue #16:

* round-trip,
* AAD context mismatch (any of file_id / sender / recipient changed),
* 1-byte ciphertext tamper,
* wrong AES key,

plus the invariant that the nonce is 12 bytes and fresh per call.
"""

from __future__ import annotations

import os

import pytest

from zerotrust.common.exceptions import CryptoError
from zerotrust.common.file_crypto import decrypt_file_blob, encrypt_file_blob


def test_file_blob_roundtrip():
    nonce, ciphertext, aes_key = encrypt_file_blob(
        b"hello",
        "file-1",
        "alice",
        "bob",
    )

    assert (
        decrypt_file_blob(aes_key, nonce, ciphertext, "file-1", "alice", "bob")
        == b"hello"
    )


@pytest.mark.parametrize(
    ("file_id", "sender", "recipient"),
    [
        ("file-2", "alice", "bob"),         # file_id changed
        ("file-1", "mallory", "bob"),       # sender changed
        ("file-1", "alice", "mallory"),     # recipient changed
    ],
)
def test_file_blob_rejects_aad_context_mismatch(file_id, sender, recipient):
    nonce, ciphertext, aes_key = encrypt_file_blob(
        b"secret",
        "file-1",
        "alice",
        "bob",
    )

    with pytest.raises(CryptoError):
        decrypt_file_blob(aes_key, nonce, ciphertext, file_id, sender, recipient)


def test_file_blob_rejects_tampered_ciphertext():
    nonce, ciphertext, aes_key = encrypt_file_blob(
        b"secret",
        "file-1",
        "alice",
        "bob",
    )
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    with pytest.raises(CryptoError):
        decrypt_file_blob(aes_key, nonce, bytes(tampered), "file-1", "alice", "bob")


def test_file_blob_rejects_wrong_key():
    nonce, ciphertext, _aes_key = encrypt_file_blob(
        b"secret",
        "file-1",
        "alice",
        "bob",
    )

    with pytest.raises(CryptoError):
        decrypt_file_blob(os.urandom(32), nonce, ciphertext, "file-1", "alice", "bob")


def test_file_blob_nonce_is_12_bytes_and_fresh():
    nonce_a, _ciphertext_a, key_a = encrypt_file_blob(b"a", "file-1", "alice", "bob")
    nonce_b, _ciphertext_b, key_b = encrypt_file_blob(b"b", "file-2", "alice", "bob")

    assert len(nonce_a) == 12
    assert len(nonce_b) == 12
    assert nonce_a != nonce_b
    assert key_a != key_b
    assert len(key_a) == 32
