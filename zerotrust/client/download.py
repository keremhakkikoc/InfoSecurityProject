from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ..common.crypto_primitives import aes_gcm_decrypt
from ..common.exceptions import CryptoError, ProtocolError, ZeroTrustError
from ..common.origin import verify_origin_struct
from ..common.protocol import make_envelope, recv_message, send_message, validate_envelope


def download_file(session: dict[str, Any], file_id: str) -> None:
    """Download a file by ID, verify its Zero-Trust security, and save to disk."""
    sock = session["sock"]
    username = session["username"]
    
    from ..common.crypto_primitives import _load_private
    private_key = _load_private(session["client_priv_pem"], session["client_password"])
    
    # 1. İstek at (DOWNLOAD_REQUEST)
    send_message(sock, make_envelope("DOWNLOAD_REQUEST", {"file_id": file_id}))
    
    # 2. Yanıt al (DOWNLOAD_RESPONSE veya ERROR)
    envelope = validate_envelope(recv_message(sock))
    if envelope["type"] == "ERROR":
        raise ProtocolError(f"Server returned error: {envelope.get('payload', {}).get('code')}")
    if envelope["type"] != "DOWNLOAD_RESPONSE":
        raise ProtocolError(f"Unexpected response: {envelope['type']}")
        
    payload = envelope["payload"]
    try:
        sender_id = payload["sender_id"]
        timestamp = payload["timestamp"]
        expiration = payload["expiration"]
        ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
        wrapped_key = base64.b64decode(payload["wrapped_key"], validate=True)
        aes_nonce = base64.b64decode(payload["aes_nonce"], validate=True)
        aes_aad = base64.b64decode(payload["aes_aad"], validate=True)
        sender_signature = base64.b64decode(payload["sender_signature"], validate=True)
        sender_cert_json = json.loads(payload["sender_cert_json"])
    except (KeyError, ValueError) as e:
        raise ProtocolError("Malformed DOWNLOAD_RESPONSE") from e
        
    # KURAL: İstemci Tarafı Sıfır Güven (Zero-Trust Doğrulaması)
    
    # Adım 1: RSA-OAEP ile AES anahtarını çöz (unwrap)
    try:
        aes_key = private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise CryptoError("Failed to unwrap AES key") from e
        
    # Adım 2: AES-GCM ile veriyi çöz ve AAD'yi doğrula
    expected_aad = f"{file_id}|{sender_id}|{username}".encode()
    if expected_aad != aes_aad:
        raise ZeroTrustError("AAD mismatch! Ciphertext substitution detected.")
        
    plaintext = aes_gcm_decrypt(
        key=aes_key,
        nonce=aes_nonce,
        ciphertext=ciphertext,
        aad=aes_aad
    ) # İçeride tag doğrulaması yapıp patlarsa CryptoError atar (Tampered Ciphertext)

    # Adım 3: Göndericinin imzasını doğrula (Origin Signature)
    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key_sha256 = hashlib.sha256(wrapped_key).hexdigest()
    
    # peer_cert asil custom JSON sertifikasidir, PEM degil. 
    peer_cert = sender_cert_json
    
    if not verify_origin_struct(
        peer_cert,
        sender_signature,
        sender=sender_id,
        recipient=username,
        file_id=file_id,
        ciphertext_sha256=ciphertext_sha256,
        wrapped_key_sha256=wrapped_key_sha256,
        timestamp=timestamp,
        expiration=expiration
    ):
        raise ZeroTrustError("Origin signature validation failed!")
    
    # Dosyayı kaydet
    download_dir = Path(f"client_{username}/downloads")
    download_dir.mkdir(parents=True, exist_ok=True)
    file_path = download_dir / file_id
    
    # Güvenli ve atomik yazma
    tmp_path = file_path.with_suffix(".tmp")
    with open(tmp_path, "wb") as f:
        f.write(plaintext)
    os.replace(tmp_path, file_path)
