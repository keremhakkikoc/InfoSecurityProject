import os
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

CERTS_DIR = "certs"

def generate_private_key():
    """Yeni bir RSA 2048-bit Private Key üretir."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def save_private_key(private_key, filename):
    """Private Key'i diske PEM formatinda kaydeder (Şifresiz)."""
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_certificate(cert, filename):
    """Sertifikayı diske PEM formatında kaydeder."""
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_private_key(filename):
    """Diskten Private Key'i yükler."""
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def load_certificate(filename):
    """Diskten X.509 sertifikasını yükler."""
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def setup_ca():
    """
    Kendi self-signed (kendi kendini imzalayan) Root CA sertifikasını
    ve private key'ini üretir.
    """
    ca_key_path = os.path.join(CERTS_DIR, "ca_private.pem")
    ca_cert_path = os.path.join(CERTS_DIR, "ca_cert.pem")
    
    if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
        print("CA zaten kurulu, mevcut anahtarlar kullanılıyor.")
        return load_private_key("ca_private.pem"), load_certificate("ca_cert.pem")
    
    print("Yeni Root CA oluşturuluyor...")
    ca_private_key = generate_private_key()
    
    # Self-signed sertifika için bilgiler (Subject = Issuer)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Istanbul"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kadikoy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ZeroTrust CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ZeroTrust Root CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 10 yıl geçerli
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    save_private_key(ca_private_key, "ca_private.pem")
    save_certificate(ca_cert, "ca_cert.pem")
    print("Root CA başarıyla oluşturuldu.")
    return ca_private_key, ca_cert

def generate_entity_cert(name, ca_private_key, ca_cert, is_server=False):
    """
    Client veya Server için private key üretir ve
    bu key'in public kısmını CA'e onaylatıp imzalı bir sertifika döndürür.
    """
    key_filename = f"{name}_private.pem"
    cert_filename = f"{name}_cert.pem"
    
    if os.path.exists(os.path.join(CERTS_DIR, key_filename)):
        print(f"{name} için sertifika zaten mevcut.")
        return load_private_key(key_filename), load_certificate(cert_filename)
        
    print(f"{name} için yeni anahtar ve sertifika üretiliyor...")
    entity_key = generate_private_key()
    
    # Entity'nin bilgileri
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ZeroTrust Entities"),
        x509.NameAttribute(NameOID.COMMON_NAME, unicode(name) if sys.version_info[0] < 3 else str(name)),
    ])
    
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name( # Issuer CA olacak
        ca_cert.subject
    ).public_key(
        entity_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 1 yıl geçerli
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )
    
    # Eklentiler (Server Authentication vs.) eklenebilir ama basitlik açısından geçiyoruz.
    
    # Sertifikayı CA'in Private Key'i ile imzalıyoruz
    entity_cert = cert_builder.sign(ca_private_key, hashes.SHA256())
    
    save_private_key(entity_key, key_filename)
    save_certificate(entity_cert, cert_filename)
    print(f"{name} için sertifika başarıyla üretildi.")
    
    return entity_key, entity_cert

if __name__ == "__main__":
    import sys
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)
        
    ca_key, ca_cert = setup_ca()
    
    # Otomatik test için varsayılan server ve default client üret
    generate_entity_cert("server", ca_key, ca_cert, is_server=True)
    generate_entity_cert("client1", ca_key, ca_cert, is_server=False)
    generate_entity_cert("client2", ca_key, ca_cert, is_server=False)
    
    print("\nTüm gerekli sertifikalar üretildi ve 'certs' dizinine kaydedildi.")
