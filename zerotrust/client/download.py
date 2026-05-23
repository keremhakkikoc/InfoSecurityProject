"""Client-side secure download flow.

The server is only a relay for encrypted packages. Per ARCHITECTURE.md
§8, the recipient must independently verify the sender certificate,
origin signature, wrapped-key binding, AES-GCM AAD, and ciphertext tag before
writing any plaintext to disk.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from ..ca.cert import verify_certificate
from ..common.exceptions import AuthError, CryptoError, ProtocolError
from ..common.file_crypto import decrypt_file_blob
from ..common.key_wrap import unwrap_aes_key
from ..common.origin import verify_origin_struct
from ..common.protocol import make_envelope, recv_message, send_message, validate_envelope


def _decode_b64_field(payload: dict[str, Any], name: str) -> bytes:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ProtocolError(f"missing {name}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError(f"{name} is not valid base64") from exc


def _load_sender_cert(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("sender_cert_json")
    if not isinstance(raw, str):
        raise ProtocolError("missing sender_cert_json")
    try:
        cert = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolError("sender_cert_json is not valid JSON") from exc
    if not isinstance(cert, dict):
        raise ProtocolError("sender_cert_json must be a JSON object")
    return cert


def _file_aad(file_id: str, sender: str, recipient: str) -> bytes:
    """Return the frozen ARCHITECTURE.md §7.7 AAD format."""
    return f"{file_id}|{sender}|{recipient}".encode()


def _download_path(username: str, file_id: str) -> Path:
    return Path(f"client_{username}") / "downloads" / file_id


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    try:
        with tmp_path.open("wb") as f:
            f.write(data)
        os.replace(tmp_path, path)
    except OSError:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def download_file(session: dict[str, Any], file_id: str) -> Path:
    """Download, verify, decrypt, and atomically save ``file_id``.

    Returns the path written on success. Any certificate, origin-signature,
    AAD, unwrap, or decrypt failure raises before the plaintext is written.
    """
    sock = session.get("sock")
    username = session.get("username")
    private_pem = session.get("client_priv_pem")
    password = session.get("client_password")
    ca_pubkey_pem = session.get("ca_pubkey_pem")

    if sock is None or not isinstance(username, str):
        raise ProtocolError("live client session is required")
    if not isinstance(private_pem, (bytes, bytearray)):
        raise ProtocolError("client private key missing from session")
    if not isinstance(password, (bytes, bytearray)):
        raise ProtocolError("client password missing from session")
    if not isinstance(ca_pubkey_pem, (bytes, bytearray)):
        raise ProtocolError("CA trust anchor missing from session")

    send_message(sock, make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))

    envelope = validate_envelope(recv_message(sock))
    if envelope["type"] == "ERROR":
        code = envelope["payload"].get("code", "ERROR")
        raise ProtocolError(str(code))
    if envelope["type"] != "DOWNLOAD_RESPONSE":
        raise ProtocolError(f"expected DOWNLOAD_RESPONSE, got {envelope['type']!r}")

    payload = envelope["payload"]
    response_file_id = payload.get("file_id")
    sender = payload.get("sender_id")
    timestamp = payload.get("timestamp")
    expiration = payload.get("expiration")
    if (
        not isinstance(response_file_id, str)
        or not hmac.compare_digest(response_file_id, file_id)
        or not isinstance(sender, str)
        or not isinstance(timestamp, int)
        or not isinstance(expiration, int)
    ):
        raise ProtocolError("malformed DOWNLOAD_RESPONSE")

    ciphertext = _decode_b64_field(payload, "ciphertext")
    wrapped_key = _decode_b64_field(payload, "wrapped_key")
    aes_nonce = _decode_b64_field(payload, "aes_nonce")
    sent_aad = _decode_b64_field(payload, "aes_aad")
    signature = _decode_b64_field(payload, "sender_signature")
    sender_cert = _load_sender_cert(payload)

    if not verify_certificate(sender_cert, bytes(ca_pubkey_pem), expected_subject=sender):
        raise AuthError("AUTH_FAILED")

    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
    if not verify_origin_struct(
        sender_cert,
        signature,
        sender=sender,
        recipient=username,
        file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp,
        expiration=expiration,
    ):
        raise AuthError("AUTH_FAILED")

    expected_aad = _file_aad(file_id, sender, username)
    if not hmac.compare_digest(sent_aad, expected_aad):
        raise CryptoError("AES-GCM AAD mismatch")

    aes_key = unwrap_aes_key(bytes(private_pem), bytes(password), wrapped_key)
    plaintext = decrypt_file_blob(
        aes_key,
        aes_nonce,
        ciphertext,
        file_id,
        sender,
        username,
    )

    output_path = _download_path(username, file_id)
    _atomic_write(output_path, plaintext)
    return output_path


__all__ = ["download_file"]
