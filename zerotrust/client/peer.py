import json
import socket
import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

def fetch_peer_cert(session: dict, username: str) -> dict | None:
    """
    İstemci tarafında hedef kullanıcının sertifikasını sunucudan çeker
    ve güvenli bir şekilde sıfır-güven (Zero-Trust) mantığıyla doğrular.
    """
    conn = session.get("conn") # Socket instance
    ca_cert = session.get("ca_cert") # İstemcinin yerel CA Trust Anchor'ı
    
    payload = {
        "action": "GET_PUBKEY",
        "username": username
    }
    
    try:
        conn.sendall(json.dumps(payload).encode('utf-8') + b'\n')
        
        # Sunucudan yanıt bekle
        response_bytes = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response_bytes += chunk
            if b'\n' in chunk:
                break
                
        if not response_bytes:
            return None
            
        response = json.loads(response_bytes.decode('utf-8').strip())
        
        if response.get("status") != "PUBKEY_RESPONSE":
            return None
            
        cert_json = response.get("cert")
        if not cert_json or "cert_pem" not in cert_json:
            return None
            
        # KURAL: İstemci Tarafı Sıfır Güven (Zero-Trust)
        # Gelen sertifikayı KENDİ yerel CA Trust Anchor'ı ile doğrula
        cert_pem_bytes = base64.b64decode(cert_json["cert_pem"])
        peer_cert = x509.load_pem_x509_certificate(cert_pem_bytes)
        
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
        
        # KURAL: Sertifikadaki subject değeri istenilen username ile EŞLEŞMELİDİR
        subject_names = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not subject_names:
            return None
            
        cert_username = subject_names[0].value
        if cert_username != username:
            # Impersonation / MitM attempt!
            return None
            
        return cert_json
        
    except Exception as e:
        # Ağ hatası, decode hatası veya Kripto doğrulama hatası (InvalidSignature vb.)
        return None
