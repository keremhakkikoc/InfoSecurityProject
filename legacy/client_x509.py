import os
import socket
import json
import struct
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

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
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print(f"Sertifika dogrulama hatasi: {e}")
        return False

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def send_msg(sock, msg_bytes):
    msg = struct.pack('>I', len(msg_bytes)) + msg_bytes
    sock.sendall(msg)

def connect_and_handshake():
    print("Sertifikalar yukleniyor...")
    client_key = load_private_key("client1_private.pem")
    client_cert = load_certificate("client1_cert.pem")
    ca_cert = load_certificate("ca_cert.pem")
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[*] Sunucuya baglaniliyor {HOST}:{PORT}...")
        client_sock.connect((HOST, PORT))
        
        # ==========================================
        # ADIM 1: ClientHello
        # ==========================================
        nonce_c = secrets.token_bytes(16)
        
        client_hello = {
            "type": "ClientHello",
            "cert": base64.b64encode(get_cert_bytes(client_cert)).decode('utf-8'),
            "nonce": base64.b64encode(nonce_c).decode('utf-8')
        }
        
        print("[*] ClientHello gonderiliyor.")
        send_msg(client_sock, json.dumps(client_hello).encode('utf-8'))
        
        # ==========================================
        # ADIM 2: ServerHello Bekleme
        # ==========================================
        server_hello_bytes = recv_msg(client_sock)
        server_hello = json.loads(server_hello_bytes.decode('utf-8'))
        
        server_cert_pem = base64.b64decode(server_hello['cert'])
        server_cert = x509.load_pem_x509_certificate(server_cert_pem)
        
        if not verify_certificate_chain(server_cert, ca_cert):
            print("[-] Sunucu sertifikasi CA tarafindan onaylanmadi! Cikiliyor.")
            return

        nonce_s = base64.b64decode(server_hello['nonce_s'])
        server_signature = base64.b64decode(server_hello['signature'])
        
        # Server Proof of Possession Dogrulamasi
        server_public_key = server_cert.public_key()
        try:
            server_public_key.verify(
                server_signature,
                nonce_c + nonce_s,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[+] Sunucu sertifikasi ve Proof-of-Possession basarili.")
        except Exception as e:
            print("[-] Sunucu imzasi dogrulanamadi:", e)
            return
            
        # ==========================================
        # ADIM 3: ClientKeyExchange Gönderme
        # ==========================================
        # Oturum için ortak sir (PreMasterSecret) uretiyoruz
        pre_master_secret = secrets.token_bytes(32)
        
        # Bunu Sunucunun sadece kendisinin (Private Key'i ile) acabilecegi sekilde Public Key'i ile sifreliyoruz
        enc_pre_master = server_public_key.encrypt(
            pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # İstemci kendi kimliğini kanıtlamak için (Proof-of-Possession) verileri imzalar
        client_signature = client_key.sign(
            nonce_c + nonce_s + pre_master_secret,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        cke = {
            "type": "ClientKeyExchange",
            "encrypted_secret": base64.b64encode(enc_pre_master).decode('utf-8'),
            "signature": base64.b64encode(client_signature).decode('utf-8')
        }
        
        print("[*] ClientKeyExchange gonderiliyor.")
        send_msg(client_sock, json.dumps(cke).encode('utf-8'))
        
        # ==========================================
        # ADIM 4: HKDF Anahtar Türetme
        # ==========================================
        print("[*] HKDF ile AES simetrik anahtarlar uretiliyor...")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64, # 32 byte C->S, 32 byte S->C
            salt=nonce_c + nonce_s,
            info=b"zero-trust-file-drop"
        )
        key_material = hkdf.derive(pre_master_secret)
        
        client_to_server_key = key_material[:32]
        server_to_client_key = key_material[32:]
        
        print(f"[SUCCESS] Handshake basariyla tamamlandi! \n[INFO] Simetrik anahtarlar baglanti boyunca kullanilmak uzere hazir.")
        
    except Exception as e:
        print(f"[-] Hata olustu: {e}")
    finally:
        client_sock.close()
        print("[*] Istemci sonlandirildi.")

if __name__ == "__main__":
    connect_and_handshake()
