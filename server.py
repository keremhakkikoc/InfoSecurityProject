import base64
import datetime
import json
import os
import secrets
import socket
import struct
import threading
import uuid
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
STORAGE_DIR = "storage"
PACKAGES_DIR = os.path.join(STORAGE_DIR, "packages")
METADATA_FILE = os.path.join(STORAGE_DIR, "metadata.json")
storage_lock = threading.Lock()


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
        now = datetime.datetime.now(datetime.timezone.utc)
        if hasattr(cert_to_check, "not_valid_before_utc"):
            not_valid_before = cert_to_check.not_valid_before_utc
            not_valid_after = cert_to_check.not_valid_after_utc
        else:
            not_valid_before = cert_to_check.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_valid_after = cert_to_check.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        if not (not_valid_before <= now <= not_valid_after):
            return False
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


def verify_package_signature(package, sender_cert):
    sender_cert.public_key().verify(
        b64d(package["signature"]),
        package_signature_payload(package),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def ensure_storage():
    os.makedirs(PACKAGES_DIR, exist_ok=True)
    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)


def load_metadata():
    ensure_storage()
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_metadata(metadata):
    ensure_storage()
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


def parse_utc(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def mark_expired(metadata):
    now = datetime.datetime.now(datetime.timezone.utc)
    changed = False
    for item in metadata:
        if item["status"] == "pending" and parse_utc(item["expires_at"]) <= now:
            item["status"] = "expired"
            changed = True
    return changed


def handle_upload(request, client_id, client_cert):
    package = request.get("package")
    if not package:
        return {"status": "ERROR", "error": "Eksik paket."}

    required = {
        "sender",
        "recipient",
        "filename",
        "expires_at",
        "file_hash",
        "file_nonce",
        "ciphertext",
        "ciphertext_hash",
        "wrapped_key",
        "signature",
    }
    if not required.issubset(package):
        return {"status": "ERROR", "error": "Paket alanlari eksik."}
    if package["sender"] != client_id:
        return {"status": "ERROR", "error": "Gonderici kimligi sertifika ile uyusmuyor."}
    if parse_utc(package["expires_at"]) <= datetime.datetime.now(datetime.timezone.utc):
        return {"status": "ERROR", "error": "Expiration zamani gecmis."}

    try:
        verify_package_signature(package, client_cert)
    except Exception as e:
        return {"status": "ERROR", "error": f"Gonderici imzasi gecersiz: {e}"}

    file_id = uuid.uuid4().hex
    package["file_id"] = file_id
    package["sender_cert"] = b64e(get_cert_bytes(client_cert))

    metadata_item = {
        "file_id": file_id,
        "sender": package["sender"],
        "recipient": package["recipient"],
        "filename": Path(package["filename"]).name,
        "upload_time": now_iso(),
        "expires_at": package["expires_at"],
        "status": "pending",
        "size": len(b64d(package["ciphertext"])),
    }
    package["filename"] = metadata_item["filename"]

    with storage_lock:
        metadata = load_metadata()
        metadata.append(metadata_item)
        save_metadata(metadata)
        package_path = os.path.join(PACKAGES_DIR, f"{file_id}.json")
        with open(package_path, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=2)

    print(f"[+] Upload kabul edildi: {file_id} ({package['sender']} -> {package['recipient']})")
    return {"status": "OK", "file_id": file_id}


def handle_list_pending(client_id):
    with storage_lock:
        metadata = load_metadata()
        if mark_expired(metadata):
            save_metadata(metadata)
        files = [
            {
                "file_id": item["file_id"],
                "sender": item["sender"],
                "filename": item["filename"],
                "upload_time": item["upload_time"],
                "expires_at": item["expires_at"],
                "size": item["size"],
            }
            for item in metadata
            if item["recipient"] == client_id and item["status"] == "pending"
        ]
    return {"status": "OK", "files": files}


def handle_download(request, client_id):
    file_id = request.get("file_id")
    if not file_id:
        return {"status": "ERROR", "error": "File ID eksik."}

    with storage_lock:
        metadata = load_metadata()
        if mark_expired(metadata):
            save_metadata(metadata)
        item = next((entry for entry in metadata if entry["file_id"] == file_id), None)

    if not item:
        return {"status": "ERROR", "error": "Dosya bulunamadi."}
    if item["recipient"] != client_id:
        print(f"[!] Yetkisiz download denemesi: {client_id} -> {file_id}")
        return {"status": "ERROR", "error": "Bu dosyayi indirme yetkiniz yok."}
    if item["status"] != "pending":
        return {"status": "ERROR", "error": f"Dosya durumu indirilebilir degil: {item['status']}"}

    package_path = os.path.join(PACKAGES_DIR, f"{file_id}.json")
    if not os.path.exists(package_path):
        return {"status": "ERROR", "error": "Paket dosyasi eksik."}

    with open(package_path, "r", encoding="utf-8") as f:
        package = json.load(f)

    print(f"[+] Download paketi gonderildi: {file_id} -> {client_id}")
    return {"status": "OK", "package": package}


def application_loop(conn, client_id, client_cert, client_to_server_key, server_to_client_key):
    while True:
        request = recv_secure(conn, client_to_server_key)
        if not request:
            return

        command = request.get("type")
        if command == "UPLOAD":
            response = handle_upload(request, client_id, client_cert)
        elif command == "LIST_PENDING":
            response = handle_list_pending(client_id)
        elif command == "DOWNLOAD":
            response = handle_download(request, client_id)
        elif command == "QUIT":
            response = {"status": "OK"}
            send_secure(conn, server_to_client_key, response)
            return
        else:
            response = {"status": "ERROR", "error": "Bilinmeyen komut."}

        send_secure(conn, server_to_client_key, response)


def handle_client(conn, addr, server_key, server_cert, ca_cert):
    print(f"[*] Yeni baglanti: {addr}")
    try:
        client_hello_bytes = recv_msg(conn)
        if not client_hello_bytes:
            print("Gecersiz ClientHello.")
            return

        client_hello = json.loads(client_hello_bytes.decode("utf-8"))
        client_cert_pem = b64d(client_hello["cert"])
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)

        if not verify_certificate_chain(client_cert, ca_cert):
            print("[-] Istemci sertifikasi dogrulanamadi, baglanti kesiliyor.")
            return

        client_id = get_common_name(client_cert)
        nonce_c = b64d(client_hello["nonce"])
        print(f"[+] Client sertifikasi onaylandi: {client_id}")

        nonce_s = secrets.token_bytes(16)
        signature_s = server_key.sign(
            nonce_c + nonce_s,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        server_hello = {
            "type": "ServerHello",
            "cert": b64e(get_cert_bytes(server_cert)),
            "nonce_s": b64e(nonce_s),
            "signature": b64e(signature_s),
        }
        send_msg(conn, json.dumps(server_hello).encode("utf-8"))

        client_key_exchange_bytes = recv_msg(conn)
        cke = json.loads(client_key_exchange_bytes.decode("utf-8"))

        pre_master_secret = server_key.decrypt(
            b64d(cke["encrypted_secret"]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        client_cert.public_key().verify(
            b64d(cke["signature"]),
            nonce_c + nonce_s + pre_master_secret,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        print("[+] Istemci Proof-of-Possession basarili.")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=nonce_c + nonce_s,
            info=b"zero-trust-file-drop",
        )
        key_material = hkdf.derive(pre_master_secret)
        client_to_server_key = key_material[:32]
        server_to_client_key = key_material[32:]

        print("[SUCCESS] Handshake tamamlandi. Uygulama komutlari bekleniyor.")
        application_loop(conn, client_id, client_cert, client_to_server_key, server_to_client_key)

    except Exception as e:
        print(f"[-] Baglanti hatasi: {e}")
    finally:
        conn.close()
        print(f"[*] Baglanti kapatildi: {addr}")


def main():
    ensure_storage()
    print("Sertifikalar yukleniyor...")
    server_key = load_private_key("server_private.pem")
    server_cert = load_certificate("server_cert.pem")
    ca_cert = load_certificate("ca_cert.pem")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Sunucu dinleniyor: {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, server_key, server_cert, ca_cert),
                daemon=True,
            )
            client_thread.start()

    except KeyboardInterrupt:
        print("\n[*] Sunucu kapatiliyor.")
        server.close()


if __name__ == "__main__":
    main()
