import argparse
import base64
import datetime
import json
import os
import secrets
import socket
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

HOST = "127.0.0.1"
PORT = 5050
CERTS_DIR = "certs"
DOWNLOADS_DIR = "downloads"


def b64e(data):
    return base64.b64encode(data).decode("utf-8")


def b64d(data):
    return base64.b64decode(data.encode("utf-8") if isinstance(data, str) else data)


def load_private_key(filename):
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_certificate(filename):
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def get_cert_bytes(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def get_common_name(cert):
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


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
    msglen = struct.unpack(">I", raw_msglen)[0]
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
    msg = struct.pack(">I", len(msg_bytes)) + msg_bytes
    sock.sendall(msg)


def send_secure(sock, key, payload):
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(payload).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    envelope = {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}
    send_msg(sock, json.dumps(envelope).encode("utf-8"))


def recv_secure(sock, key):
    envelope_bytes = recv_msg(sock)
    if not envelope_bytes:
        return None
    envelope = json.loads(envelope_bytes.decode("utf-8"))
    plaintext = AESGCM(key).decrypt(b64d(envelope["nonce"]), b64d(envelope["ciphertext"]), None)
    return json.loads(plaintext.decode("utf-8"))


def package_signature_payload(package):
    signed_fields = {
        "sender": package["sender"],
        "recipient": package["recipient"],
        "filename": package["filename"],
        "expires_at": package["expires_at"],
        "file_hash": package["file_hash"],
        "file_nonce": package["file_nonce"],
        "ciphertext_hash": package["ciphertext_hash"],
        "wrapped_key": package["wrapped_key"],
    }
    return json.dumps(signed_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_package(package, private_key):
    return private_key.sign(
        package_signature_payload(package),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_package_signature(package, sender_cert):
    sender_cert.public_key().verify(
        b64d(package["signature"]),
        package_signature_payload(package),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def sha256_b64(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return b64e(digest.finalize())


def connect_and_handshake(client_name):
    print("Sertifikalar yukleniyor...")
    client_key = load_private_key(f"{client_name}_private.pem")
    client_cert = load_certificate(f"{client_name}_cert.pem")
    ca_cert = load_certificate("ca_cert.pem")

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[*] Sunucuya baglaniliyor {HOST}:{PORT}...")
        client_sock.connect((HOST, PORT))

        nonce_c = secrets.token_bytes(16)
        client_hello = {
            "type": "ClientHello",
            "cert": b64e(get_cert_bytes(client_cert)),
            "nonce": b64e(nonce_c),
        }

        print("[*] ClientHello gonderiliyor.")
        send_msg(client_sock, json.dumps(client_hello).encode("utf-8"))

        server_hello_bytes = recv_msg(client_sock)
        server_hello = json.loads(server_hello_bytes.decode("utf-8"))

        server_cert_pem = b64d(server_hello["cert"])
        server_cert = x509.load_pem_x509_certificate(server_cert_pem)

        if not verify_certificate_chain(server_cert, ca_cert):
            print("[-] Sunucu sertifikasi CA tarafindan onaylanmadi! Cikiliyor.")
            client_sock.close()
            return None

        nonce_s = b64d(server_hello["nonce_s"])
        server_signature = b64d(server_hello["signature"])

        server_public_key = server_cert.public_key()
        server_public_key.verify(
            server_signature,
            nonce_c + nonce_s,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        print("[+] Sunucu sertifikasi ve Proof-of-Possession basarili.")

        pre_master_secret = secrets.token_bytes(32)
        enc_pre_master = server_public_key.encrypt(
            pre_master_secret,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        client_signature = client_key.sign(
            nonce_c + nonce_s + pre_master_secret,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        cke = {
            "type": "ClientKeyExchange",
            "encrypted_secret": b64e(enc_pre_master),
            "signature": b64e(client_signature),
        }

        print("[*] ClientKeyExchange gonderiliyor.")
        send_msg(client_sock, json.dumps(cke).encode("utf-8"))

        print("[*] HKDF ile AES simetrik anahtarlar uretiliyor...")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=nonce_c + nonce_s,
            info=b"zero-trust-file-drop",
        )
        key_material = hkdf.derive(pre_master_secret)

        print("[SUCCESS] Handshake tamamlandi. Komut menusu aciliyor.")
        return {
            "sock": client_sock,
            "client_to_server_key": key_material[:32],
            "server_to_client_key": key_material[32:],
            "client_key": client_key,
            "client_cert": client_cert,
            "ca_cert": ca_cert,
            "client_name": get_common_name(client_cert),
        }
    except Exception as e:
        print(f"[-] Hata olustu: {e}")
        client_sock.close()
        return None


def upload_file(session):
    path_text = input("Yuklenecek dosya yolu: ").strip().strip('"')
    recipient = input("Alici kullanici adi (orn: client2): ").strip()
    expiry_hours_text = input("Kac saat sonra expire olsun? [24]: ").strip() or "24"

    path = Path(path_text)
    if not path.is_file():
        print("[-] Dosya bulunamadi.")
        return

    try:
        recipient_cert = load_certificate(f"{recipient}_cert.pem")
    except FileNotFoundError:
        print(f"[-] {recipient} icin sertifika bulunamadi.")
        return

    plaintext = path.read_bytes()
    file_key = AESGCM.generate_key(bit_length=256)
    file_nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(file_key).encrypt(file_nonce, plaintext, None)

    wrapped_key = recipient_cert.public_key().encrypt(
        file_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    expires_at = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=float(expiry_hours_text))
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    package = {
        "sender": session["client_name"],
        "recipient": recipient,
        "filename": path.name,
        "expires_at": expires_at,
        "file_hash": sha256_b64(plaintext),
        "file_nonce": b64e(file_nonce),
        "ciphertext": b64e(ciphertext),
        "ciphertext_hash": sha256_b64(ciphertext),
        "wrapped_key": b64e(wrapped_key),
    }
    package["signature"] = b64e(sign_package(package, session["client_key"]))

    send_secure(
        session["sock"],
        session["client_to_server_key"],
        {"type": "UPLOAD", "package": package},
    )
    response = recv_secure(session["sock"], session["server_to_client_key"])
    if response.get("status") == "OK":
        print(f"[+] Dosya yuklendi. File ID: {response['file_id']}")
    else:
        print(f"[-] Yukleme reddedildi: {response.get('error')}")


def list_pending_files(session):
    send_secure(session["sock"], session["client_to_server_key"], {"type": "LIST_PENDING"})
    response = recv_secure(session["sock"], session["server_to_client_key"])
    if response.get("status") != "OK":
        print(f"[-] Listeleme hatasi: {response.get('error')}")
        return

    files = response.get("files", [])
    if not files:
        print("[*] Bekleyen dosya yok.")
        return

    print("\nBekleyen dosyalar:")
    for item in files:
        print(
            f"- ID: {item['file_id']} | Gonderen: {item['sender']} | "
            f"Dosya: {item['filename']} | Expire: {item['expires_at']}"
        )


def download_file(session):
    file_id = input("Indirilecek File ID: ").strip()
    send_secure(session["sock"], session["client_to_server_key"], {"type": "DOWNLOAD", "file_id": file_id})
    response = recv_secure(session["sock"], session["server_to_client_key"])
    if response.get("status") != "OK":
        print(f"[-] Indirme reddedildi: {response.get('error')}")
        return

    package = response["package"]
    sender_cert = x509.load_pem_x509_certificate(b64d(package["sender_cert"]))

    if not verify_certificate_chain(sender_cert, session["ca_cert"]):
        print("[-] Gonderici sertifikasi CA tarafindan dogrulanamadi.")
        return
    if get_common_name(sender_cert) != package["sender"]:
        print("[-] Gonderici sertifikasi paket kimligiyle uyusmuyor.")
        return

    try:
        file_key = session["client_key"].decrypt(
            b64d(package["wrapped_key"]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        plaintext = AESGCM(file_key).decrypt(b64d(package["file_nonce"]), b64d(package["ciphertext"]), None)
        if sha256_b64(plaintext) != package["file_hash"]:
            print("[-] Dosya hash kontrolu basarisiz.")
            return
        verify_package_signature(package, sender_cert)
    except Exception as e:
        print(f"[-] Paket cozuldu/dogrulandi ama guvenlik kontrolu basarisiz: {e}")
        return

    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    output_path = Path(DOWNLOADS_DIR) / f"{package['file_id']}_{package['filename']}"
    output_path.write_bytes(plaintext)
    print(f"[+] Dosya indirildi ve imza dogrulandi: {output_path}")


def menu_loop(session):
    while True:
        print("\n1. Dosya Yukle")
        print("2. Gelen Dosyalari Listele")
        print("3. Dosya Indir")
        print("4. Cikis")
        choice = input("Secim: ").strip()

        if choice == "1":
            upload_file(session)
        elif choice == "2":
            list_pending_files(session)
        elif choice == "3":
            download_file(session)
        elif choice == "4":
            send_secure(session["sock"], session["client_to_server_key"], {"type": "QUIT"})
            recv_secure(session["sock"], session["server_to_client_key"])
            break
        else:
            print("[-] Gecersiz secim.")


def main():
    parser = argparse.ArgumentParser(description="Zero-trust file drop client")
    parser.add_argument("--user", default="client1", help="Kullanilacak istemci kimligi (orn: client1/client2)")
    args = parser.parse_args()

    session = connect_and_handshake(args.user)
    if not session:
        return

    try:
        menu_loop(session)
    finally:
        session["sock"].close()
        print("[*] Istemci sonlandirildi.")


if __name__ == "__main__":
    main()
