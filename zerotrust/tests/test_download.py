"""Recipient-side verification tests for secure download.

These tests exercise the client without trusting a live server: the fake
socket returns a DOWNLOAD_RESPONSE package, and ``download_file`` must verify
the CA-signed sender cert, origin signature, wrapped AES key, AES-GCM AAD, and
ciphertext tag before writing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from zerotrust.ca import cert as cert_mod
from zerotrust.client.download import download_file
from zerotrust.common import crypto_primitives as cp
from zerotrust.common.exceptions import AuthError, CryptoError
from zerotrust.common.file_crypto import encrypt_file_blob
from zerotrust.common.key_wrap import wrap_aes_key_for
from zerotrust.common.origin import sign_origin_struct
from zerotrust.common.protocol import make_envelope, pack_message


CA_PASSWORD = b"ca-test-password"
ALICE_PASSWORD = b"alice-test-password"
BOB_PASSWORD = b"bob-test-password"


class FakeSocket:
    def __init__(self, incoming: bytes) -> None:
        self._incoming = bytearray(incoming)
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, n: int) -> bytes:
        if not self._incoming:
            return b""
        chunk = self._incoming[:n]
        del self._incoming[:n]
        return bytes(chunk)


@pytest.fixture
def keys():
    ca_priv, ca_pub = cp.generate_rsa_keypair(CA_PASSWORD)
    alice_priv, alice_pub = cp.generate_rsa_keypair(ALICE_PASSWORD)
    bob_priv, bob_pub = cp.generate_rsa_keypair(BOB_PASSWORD)
    alice_cert = cert_mod.issue_certificate(
        "alice",
        alice_pub,
        ca_priv,
        CA_PASSWORD,
    )
    bob_cert = cert_mod.issue_certificate("bob", bob_pub, ca_priv, CA_PASSWORD)
    return {
        "ca_pub": ca_pub,
        "alice_priv": alice_priv,
        "alice_cert": alice_cert,
        "bob_priv": bob_priv,
        "bob_cert": bob_cert,
    }


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _make_package(
    keys: dict[str, Any],
    *,
    plaintext: bytes = b"secret for bob",
    aad_override: bytes | None = None,
    ciphertext_override: bytes | None = None,
    signature_override: bytes | None = None,
) -> tuple[str, dict[str, Any]]:
    file_id = str(uuid.uuid4())
    timestamp = int(time.time())
    expiration = timestamp + 3600
    nonce, ciphertext, aes_key = encrypt_file_blob(plaintext, file_id, "alice", "bob")
    wrapped_key = wrap_aes_key_for(keys["bob_cert"], aes_key)

    if ciphertext_override is not None:
        ciphertext = ciphertext_override

    signature = sign_origin_struct(
        keys["alice_priv"],
        ALICE_PASSWORD,
        sender="alice",
        recipient="bob",
        file_id=file_id,
        ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
        wrapped_key_sha256=hashlib.sha256(wrapped_key).hexdigest(),
        timestamp=timestamp,
        expiration=expiration,
    )
    if signature_override is not None:
        signature = signature_override

    payload = {
        "file_id": file_id,
        "sender_id": "alice",
        "timestamp": timestamp,
        "expiration": expiration,
        "ciphertext": _b64(ciphertext),
        "wrapped_key": _b64(wrapped_key),
        "aes_nonce": _b64(nonce),
        "aes_aad": _b64(
            aad_override if aad_override is not None else f"{file_id}|alice|bob".encode()
        ),
        "sender_signature": _b64(signature),
        "sender_cert_json": json.dumps(keys["alice_cert"], sort_keys=True),
    }
    return file_id, payload


def _session(keys: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    response1 = pack_message(make_envelope("DOWNLOAD_RESPONSE", payload))
    response2 = pack_message(make_envelope("ACK_OK", {"file_id": payload["file_id"]}))
    sock = FakeSocket(response1 + response2)
    return {
        "sock": sock,
        "username": "bob",
        "client_priv_pem": keys["bob_priv"],
        "client_password": BOB_PASSWORD,
        "ca_pubkey_pem": keys["ca_pub"],
    }


def test_download_verifies_decrypts_and_writes(keys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file_id, payload = _make_package(keys, plaintext=b"top secret")

    output_path = download_file(_session(keys, payload), file_id)

    assert output_path == Path("client_bob/downloads") / file_id
    assert output_path.read_bytes() == b"top secret"


def test_download_rejects_wrong_aad_without_writing(keys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file_id, payload = _make_package(keys, aad_override=b"wrong|aad|context")

    with pytest.raises(CryptoError):
        download_file(_session(keys, payload), file_id)

    assert not (Path("client_bob/downloads") / file_id).exists()


def test_download_rejects_tampered_ciphertext_without_writing(keys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    file_id, payload = _make_package(keys, plaintext=b"top secret")
    ciphertext = bytearray(base64.b64decode(payload["ciphertext"], validate=True))
    ciphertext[0] ^= 0x01
    payload["ciphertext"] = _b64(bytes(ciphertext))
    payload["sender_signature"] = _b64(
        sign_origin_struct(
            keys["alice_priv"],
            ALICE_PASSWORD,
            sender="alice",
            recipient="bob",
            file_id=file_id,
            ciphertext_sha256=hashlib.sha256(bytes(ciphertext)).hexdigest(),
            wrapped_key_sha256=hashlib.sha256(
                base64.b64decode(payload["wrapped_key"], validate=True)
            ).hexdigest(),
            timestamp=payload["timestamp"],
            expiration=payload["expiration"],
        )
    )

    with pytest.raises(CryptoError):
        download_file(_session(keys, payload), file_id)

    assert not (Path("client_bob/downloads") / file_id).exists()


def test_download_rejects_bad_sender_signature_without_writing(
    keys,
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    file_id, payload = _make_package(keys, signature_override=b"not-a-valid-signature")

    with pytest.raises(AuthError):
        download_file(_session(keys, payload), file_id)

    assert not (Path("client_bob/downloads") / file_id).exists()
