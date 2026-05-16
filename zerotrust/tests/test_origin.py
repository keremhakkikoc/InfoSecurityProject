"""Tests for sender origin signatures over ARCHITECTURE.md §7.6 structs."""

from __future__ import annotations

import pytest

from zerotrust.common.crypto_primitives import generate_rsa_keypair
from zerotrust.common.origin import sign_origin_struct, verify_origin_struct


PASSWORD = b"origin-test-password"


@pytest.fixture(scope="module")
def alice_keypair():
    return generate_rsa_keypair(PASSWORD)


@pytest.fixture
def alice_cert(alice_keypair):
    _, public_pem = alice_keypair
    return {"subject": "alice", "public_key_pem": public_pem.decode("ascii")}


@pytest.fixture
def baseline_fields():
    return {
        "sender": "alice",
        "recipient": "bob",
        "file_id": "file-123",
        "ciphertext_sha256": "a" * 64,
        "wrapped_key_sha256": "b" * 64,
        "timestamp": 1_746_360_000,
        "expiration": 1_746_446_400,
    }


def test_sign_with_sender_key_verifies(alice_keypair, alice_cert, baseline_fields):
    private_pem, _ = alice_keypair
    signature = sign_origin_struct(private_pem, PASSWORD, **baseline_fields)

    assert verify_origin_struct(alice_cert, signature, **baseline_fields) is True


@pytest.mark.parametrize(
    "field",
    [
        "sender",
        "recipient",
        "file_id",
        "ciphertext_sha256",
        "wrapped_key_sha256",
        "timestamp",
        "expiration",
    ],
)
def test_tamper_any_field_invalidates(
    field,
    alice_keypair,
    alice_cert,
    baseline_fields,
):
    private_pem, _ = alice_keypair
    signature = sign_origin_struct(private_pem, PASSWORD, **baseline_fields)

    tampered_fields = baseline_fields.copy()
    if field in {"timestamp", "expiration"}:
        tampered_fields[field] += 1
    else:
        tampered_fields[field] = f"{tampered_fields[field]}-tampered"

    assert verify_origin_struct(alice_cert, signature, **tampered_fields) is False


def test_tamper_signature_byte_invalidates(alice_keypair, alice_cert, baseline_fields):
    private_pem, _ = alice_keypair
    signature = bytearray(sign_origin_struct(private_pem, PASSWORD, **baseline_fields))
    signature[0] ^= 0x01

    assert verify_origin_struct(alice_cert, bytes(signature), **baseline_fields) is False


def test_reordered_input_fields_still_verify(alice_keypair, alice_cert, baseline_fields):
    private_pem, _ = alice_keypair
    reversed_fields = dict(reversed(list(baseline_fields.items())))

    signature = sign_origin_struct(private_pem, PASSWORD, **reversed_fields)

    assert verify_origin_struct(alice_cert, signature, **baseline_fields) is True


def test_verify_fails_closed_without_public_key(baseline_fields):
    assert verify_origin_struct({}, b"not-a-signature", **baseline_fields) is False


def test_verify_fails_closed_with_malformed_public_key(baseline_fields):
    cert = {"subject": "alice", "public_key_pem": "not pem"}

    assert verify_origin_struct(cert, b"not-a-signature", **baseline_fields) is False
