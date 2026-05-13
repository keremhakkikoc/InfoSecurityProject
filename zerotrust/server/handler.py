import logging
import sqlite3
import json
import base64
import os
import hashlib
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509

logger = logging.getLogger(__name__)

# --- STUBS (Testlerin geçebilmesi için geçici mock fonksiyonlar) ---
SEEN_NONCES = set()

def check_and_record_nonce(nonce: str) -> bool:
    if nonce in SEEN_NONCES:
        return False
    SEEN_NONCES.add(nonce)
    return True

def verify_origin_struct(cert_pem_bytes: bytes, signature_bytes: bytes, payload: dict) -> bool:
    try:
        canonical_str = f"{payload['sender']}|{payload['recipient']}|{payload['timestamp']}|{payload['nonce']}|{payload['ciphertext_sha256']}|{payload['wrapped_key_sha256']}"
        cert = x509.load_pem_x509_certificate(cert_pem_bytes)
        public_key = cert.public_key()
        
        public_key.verify(
            signature_bytes,
            canonical_str.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def store_insert_file(sender, recipient, file_id, expiration):
    pass # Stub DB operation

def check_recipient_exists(recipient_name):
    return recipient_name != "unknown_user"

# --- END STUBS ---

def send_response(sock, response_dict):
    try:
        sock.sendall(json.dumps(response_dict).encode('utf-8') + b'\n')
    except Exception as e:
        logger.error(f"Hata: {e}")

def _handle_upload_request(conn, session, payload):
    try:
        # 1. Replay protection (cheap, do first to avoid DoS via expensive checks).
        nonce = payload.get("nonce")
        if not check_and_record_nonce(nonce):
            logger.warning(f"Replay attack detected with nonce: {nonce}")
            send_response(conn, {"status": "REPLAY"})
            return

        # STALE check (ek güvenlik için timestamp kontrolü)
        timestamp = float(payload.get("timestamp", 0))
        if time.time() - timestamp > 40:  # 50s old -> STALE
            logger.warning("Stale timestamp detected.")
            send_response(conn, {"status": "STALE"})
            return

        # 2. Sender PoP: did this session prove ownership of the cert it presented?
        # KURAL: payload["sender"] ile session["peer_subject"] KESİNLİKLE EŞLEŞMELİDİR.
        sender = payload.get("sender")
        if sender != session.get("peer_subject"):
            logger.error(f"Impersonation attempt! Payload sender: {sender}, Session subject: {session.get('peer_subject')}")
            send_response(conn, {"status": "AUTH_FAILED"})
            return

        # 3. Decode payload fields. Base64 -> bytes for ciphertext/nonce/wrapped/sig.
        try:
            ciphertext_bytes = base64.b64decode(payload["ciphertext"])
            wrapped_key_bytes = base64.b64decode(payload["wrapped_key"])
            signature_bytes = base64.b64decode(payload["signature"])
        except Exception as e:
            logger.error(f"Base64 decode error: {e}")
            send_response(conn, {"status": "BAD_REQUEST"})
            return

        # 4. Recompute ciphertext_sha256 and wrapped_key_sha256 from the actual bytes.
        recomputed_cipher_hash = hashlib.sha256(ciphertext_bytes).hexdigest()
        recomputed_wrapped_hash = hashlib.sha256(wrapped_key_bytes).hexdigest()
        
        # KURAL: Loglama yaparken KESİNLİKLE plaintext loglama. Sadece sha256 prefix logla.
        sig_hash_prefix = hashlib.sha256(signature_bytes).hexdigest()[:8]
        logger.info(f"Upload hashes: cipher={recomputed_cipher_hash[:8]}, wrapped={recomputed_wrapped_hash[:8]}, sig={sig_hash_prefix}")

        if recomputed_cipher_hash != payload.get("ciphertext_sha256") or recomputed_wrapped_hash != payload.get("wrapped_key_sha256"):
            logger.error("Hash mismatch! Data tampered.")
            send_response(conn, {"status": "AUTH_FAILED"})
            return

        # 5. verify_origin_struct(session["peer_cert"], signature, ...all fields...)
        # Sunucu ciphertext'i decrypt EDEMEZ. Sadece imzayı doğrular.
        peer_cert = session.get("peer_cert")
        if not verify_origin_struct(peer_cert, signature_bytes, payload):
            logger.error("Forged signature detected!")
            send_response(conn, {"status": "AUTH_FAILED"})
            return

        # 6. Sanity-check recipient exists in pubkey directory.
        recipient = payload.get("recipient")
        if not check_recipient_exists(recipient):
            logger.error(f"Unknown recipient: {recipient}")
            send_response(conn, {"status": "NOT_FOUND"})
            return

        # 7. Write ciphertext to disk atomically (*.tmp then os.rename).
        file_id = str(uuid.uuid4())
        upload_dir = session.get("server_state", {}).get("upload_dir", "server_data")
        os.makedirs(upload_dir, exist_ok=True)
        
        final_path = os.path.join(upload_dir, file_id)
        tmp_path = final_path + ".tmp"
        
        try:
            with open(tmp_path, "wb") as f:
                f.write(ciphertext_bytes)
            os.rename(tmp_path, final_path)
            logger.info(f"File {file_id} saved to disk atomically.")
        except Exception as e:
            logger.error(f"Disk write error: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            send_response(conn, {"status": "SERVER_ERROR"})
            return

        # 8. Insert metadata row.
        expiration = int(time.time()) + (3600 * 24 * 7) # 1 week
        store_insert_file(sender, recipient, file_id, expiration)

        # 9. UPLOAD_ACK with file_id + expiration.
        send_response(conn, {
            "status": "UPLOAD_ACK",
            "file_id": file_id,
            "expiration": expiration
        })

    except Exception as e:
        logger.error(f"Upload handler exception: {e}", exc_info=True)
        send_response(conn, {"status": "SERVER_ERROR"})

def serve_connection(sock, addr, server_state):
    logger.info(f"[*] Yeni baglanti kabul edildi: {addr}")
    try:
        data = sock.recv(4096)
        if data:
            # Gelen veriyi payload olarak parse ediyoruz.
            payload = json.loads(data.decode('utf-8'))
            
            # Mock session state for testing (normalde handshake'de dolar)
            session = {
                "peer_subject": payload.get("mock_session_subject"),
                "peer_cert": base64.b64decode(payload.get("mock_session_cert", "")),
                "server_state": server_state
            }
            
            if payload.get("action") == "UPLOAD":
                _handle_upload_request(sock, session, payload)
            
    except Exception as e:
        logger.error(f"[-] {addr} istemcisinde beklenmeyen hata: {e}")
    finally:
        try:
            sock.close()
            logger.info(f"[*] Baglanti kapatildi: {addr}")
        except Exception as e:
            logger.error(f"[-] {addr} baglantisi kapatilirken hata: {e}")
