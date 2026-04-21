import os
import socket
import threading
import json
import struct
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

# Ayarlar
HOST = '127.0.0.1'
PORT = 5050
CERTS_DIR = 'certs'

def load_private_key(filename):
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_certificate(filename):
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def get_cert_bytes(cert):
    return cert.public_bytes(serialization.Encoding.PEM)

def verify_certificate_chain(cert_to_check, ca_cert):
    """
    Basit sertifika doğrulama. (İmzanın CA'in public key'i ile onaylanması)
    """
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm,
        )
        # Süre kontrolü
        from datetime import datetime
        now = datetime.utcnow()
        if not (cert_to_check.not_valid_before <= now <= cert_to_check.not_valid_after):
            return False
        return True
    except Exception as e:
        print(f"Sertifika doğrulama hatası: {e}")
        return False

def recv_msg(sock):
    """Socket üzerinden uzunluk-kısıtlı(length-prefixed) mesaj okur."""
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def recvall(sock, n):
    """n byte gelene kadar okur."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def send_msg(sock, msg_bytes):
    """Mesajı başlığına 4 byte uzunluk ekleyerek yollar."""
    msg = struct.pack('>I', len(msg_bytes)) + msg_bytes
    sock.sendall(msg)

def handle_client(conn, addr, server_key, server_cert, ca_cert):
    print(f"[*] Yeni bağlantı: {addr}")
    try:
        # ==========================================
        # ADIM 1: ClientHello Bekleme
        # ==========================================
        client_hello_bytes = recv_msg(conn)
        if not client_hello_bytes:
            print("Gecersiz ClientHello.")
            return
            
        client_hello = json.loads(client_hello_bytes.decode('utf-8'))
        
        # Gelen sertifikayı yükle ve CA ile doğrula
        client_cert_pem = base64.b64decode(client_hello['cert'])
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)
        
        if not verify_certificate_chain(client_cert, ca_cert):
            print("[-] Istemci sertifikasi dogrulanamadi, baglanti kesiliyor.")
            conn.close()
            return

        nonce_c = base64.b64decode(client_hello['nonce'])
        print(f"[+] Client sertifikası onaylandı. Nonce alındı.")

        # ==========================================
        # ADIM 2: ServerHello ve Proof Gönderme
        # ==========================================
        nonce_s = secrets.token_bytes(16)
        
        # Proof of Possession: Nonce_C ve Nonce_S imzalanır
        data_to_sign = nonce_c + nonce_s
        signature_s = server_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        server_hello = {
            "type": "ServerHello",
            "cert": base64.b64encode(get_cert_bytes(server_cert)).decode('utf-8'),
            "nonce_s": base64.b64encode(nonce_s).decode('utf-8'),
            "signature": base64.b64encode(signature_s).decode('utf-8')
        }
        
        send_msg(conn, json.dumps(server_hello).encode('utf-8'))
        
        # ==========================================
        # ADIM 3: ClientKeyExchange Bekleme
        # ==========================================
        client_key_exchange_bytes = recv_msg(conn)
        cke = json.loads(client_key_exchange_bytes.decode('utf-8'))
        
        enc_pre_master = base64.b64decode(cke['encrypted_secret'])
        client_signature = base64.b64decode(cke['signature'])
        
        # PreMasterSecret'i server'ın private key'i ile aç (OADEP ile güvenli RSA şifre çözme)
        pre_master_secret = server_key.decrypt(
            enc_pre_master,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Client İmzası Doğrulama: İstemci Nonce'ları ve PreMasterSecret'i imzaladı mı?
        client_public_key = client_cert.public_key()
        try:
            client_public_key.verify(
                client_signature,
                nonce_c + nonce_s + pre_master_secret,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[+] Istemci Proof-of-Possession basarili.")
        except Exception as e:
            print("[-] Istemci imzasi dogrulanamadi, baglanti kesiliyor.", e)
            conn.close()
            return
            
        # ==========================================
        # ADIM 4: HKDF Anahtar Türetme
        # ==========================================
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64, # 32 byte C->S, 32 byte S->C için
            salt=nonce_c + nonce_s,
            info=b"zero-trust-file-drop"
        )
        key_material = hkdf.derive(pre_master_secret)
        
        client_to_server_key = key_material[:32]
        server_to_client_key = key_material[32:]
        
        print(f"[SUCCESS] Handshake tamamlandi! Guvenli oturum anahtari olusturuldu.")
        
        # Buradan sonraki aşamalarda file metadata, yükleme vs bu simetrik AES anahtarları ile yapılır.
        # Simdilik sadece handshake tasarımı gösterildi.

    except Exception as e:
        print(f"[-] Baglanti hatasi: {e}")
    finally:
        conn.close()
        print(f"[*] Baglanti kapatildi: {addr}")

def main():
    print("Sertifikalar yukleniyor...")
    server_key = load_private_key("server_private.pem")
    server_cert = load_certificate("server_cert.pem")
    ca_cert = load_certificate("ca_cert.pem")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Sunucu dinleniyor: {HOST}:{PORT}")
    
    try:
        while True:
            conn, addr = server.accept()
            # Multi-threading destegi
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, server_key, server_cert, ca_cert)
            )
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[*] Sunucu kapatiliyor.")
        server.close()

if __name__ == "__main__":
    main()
