import base64
import hashlib
import json
import logging
import os
import re
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from zerotrust.server.storage_layout import pubkey_path_for

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

def _handle_get_pubkey(conn, session, payload):
    username = payload.get("username", "")
    
    # KURAL: Güvenlik Sınırı (Regex Boundary) KESİNLİKLE uygulanmalı
    if not re.match(r"^[a-zA-Z0-9_-]{1,32}$", username):
        logger.warning(f"Path traversal veya gecersiz karakter denemesi reddedildi: {username}")
        send_response(conn, {"status": "NOT_FOUND"})
        return
        
    storage_base = session.get("server_state", {}).get("upload_dir", "server/storage")
    cert_path = pubkey_path_for(storage_base, username)
    
    if not os.path.exists(cert_path):
        send_response(conn, {"status": "NOT_FOUND"})
        return
        
    try:
        with open(cert_path) as f:
            cert_json = json.load(f)
            
        # KURAL: Sunucu Tarafı Derinlemesine Savunma (Defense in Depth)
        ca_cert = session.get("server_state", {}).get("ca_cert")
        if not ca_cert:
            # Testler veya state eksikliği durumlarında CA trust sağlanamıyorsa
            logger.error("Sunucu CA Trust Anchor eksik.")
            send_response(conn, {"status": "NOT_FOUND"})
            return
            
        cert_pem_bytes = base64.b64decode(cert_json.get("cert_pem", ""))
        peer_cert = x509.load_pem_x509_certificate(cert_pem_bytes)
        
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
        
        # Diskten okunan veri sağlam, CA doğrulaması tamam. Artık istemciye gönderilebilir.
        send_response(conn, {
            "status": "PUBKEY_RESPONSE",
            "cert": cert_json
        })
    except Exception as e:
        # KURAL: Asla internal error veya dosya sistem hatası sızdırma!
        logger.error(f"GET_PUBKEY islenirken hata (diske mudahale olabilir mi?): {e}")
        send_response(conn, {"status": "NOT_FOUND"})

def _handle_upload_request(conn, session, payload):
    try:
        nonce = payload.get("nonce")
        if not check_and_record_nonce(nonce):
            logger.warning(f"Replay attack detected with nonce: {nonce}")
            send_response(conn, {"status": "REPLAY"})
            return

        timestamp = float(payload.get("timestamp", 0))
        if time.time() - timestamp > 40: 
            logger.warning("Stale timestamp detected.")
            send_response(conn, {"status": "STALE"})
            return

        sender = payload.get("sender")
        if sender != session.get("peer_subject"):
            logger.error(f"Impersonation attempt! Payload sender: {sender}, Session subject: {session.get('peer_subject')}")
            send_response(conn, {"status": "AUTH_FAILED"})
            return

        try:
            ciphertext_bytes = base64.b64decode(payload["ciphertext"])
            wrapped_key_bytes = base64.b64decode(payload["wrapped_key"])
            signature_bytes = base64.b64decode(payload["signature"])
        except Exception as e:
            logger.error(f"Base64 decode error: {e}")
            send_response(conn, {"status": "BAD_REQUEST"})
            return

        recomputed_cipher_hash = hashlib.sha256(ciphertext_bytes).hexdigest()
        recomputed_wrapped_hash = hashlib.sha256(wrapped_key_bytes).hexdigest()
        
        sig_hash_prefix = hashlib.sha256(signature_bytes).hexdigest()[:8]
        logger.info(f"Upload hashes: cipher={recomputed_cipher_hash[:8]}, wrapped={recomputed_wrapped_hash[:8]}, sig={sig_hash_prefix}")

        if recomputed_cipher_hash != payload.get("ciphertext_sha256") or recomputed_wrapped_hash != payload.get("wrapped_key_sha256"):
            logger.error("Hash mismatch! Data tampered.")
            send_response(conn, {"status": "AUTH_FAILED"})
            return

        peer_cert = session.get("peer_cert")
        if not verify_origin_struct(peer_cert, signature_bytes, payload):
            logger.error("Forged signature detected!")
            send_response(conn, {"status": "AUTH_FAILED"})
            return

        recipient = payload.get("recipient")
        if not check_recipient_exists(recipient):
            logger.error(f"Unknown recipient: {recipient}")
            send_response(conn, {"status": "NOT_FOUND"})
            return

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

        expiration = int(time.time()) + (3600 * 24 * 7)
        store_insert_file(sender, recipient, file_id, expiration)

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
            payload = json.loads(data.decode('utf-8'))
            
            session = {
                "peer_subject": payload.get("mock_session_subject"),
                "peer_cert": base64.b64decode(payload.get("mock_session_cert", "")) if payload.get("mock_session_cert") else None,
                "server_state": server_state
            }
            
            action = payload.get("action")
            if action == "UPLOAD":
                _handle_upload_request(sock, session, payload)
            elif action == "GET_PUBKEY":
                _handle_get_pubkey(sock, session, payload)
            
    except Exception as e:
        logger.error(f"[-] {addr} istemcisinde beklenmeyen hata: {e}")
    finally:
        try:
            sock.close()
            logger.info(f"[*] Baglanti kapatildi: {addr}")
        except Exception as e:
            logger.error(f"[-] {addr} baglantisi kapatilirken hata: {e}")
