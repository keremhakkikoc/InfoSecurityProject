import unittest
import socket
import json
import base64
import time
import os
import threading
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import socketserver
import zerotrust.server.handler as handler

class ZeroTrustRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        handler.serve_connection(self.request, self.client_address, self.server.server_state)

class ZeroTrustServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, server_address, RequestHandlerClass, server_state):
        super().__init__(server_address, RequestHandlerClass)
        self.server_state = server_state
from zerotrust.client.peer import fetch_peer_cert
import zerotrust.server.storage_layout as storage_layout

class TestPubkeyDirectory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Gerçekçi CA ve Client Cert oluştur
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA")])
        cls.ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            cls.ca_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(cls.ca_key, hashes.SHA256())

        cls.client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        c_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"bob")])
        cls.client_cert = x509.CertificateBuilder().subject_name(c_sub).issuer_name(issuer).public_key(
            cls.client_key.public_key()).serial_number(2).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(cls.ca_key, hashes.SHA256())

        cls.cert_bytes = cls.client_cert.public_bytes(serialization.Encoding.PEM)

    def setUp(self):
        self.upload_dir = f"server_data_test_{uuid.uuid4()}"
        pubkeys_dir = os.path.join(self.upload_dir, "pubkeys")
        os.makedirs(pubkeys_dir, exist_ok=True)
        
        self.server_state = {
            "upload_dir": self.upload_dir,
            "ca_cert": self.ca_cert  # Sunucu içi Defense-in-depth CA verify için
        }
        
        self.server = ZeroTrustServer(('127.0.0.1', 0), ZeroTrustRequestHandler, self.server_state)
        self.port = self.server.server_address[1]
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        
        # Cleanup
        if os.path.exists(self.upload_dir):
            pubkeys_dir = os.path.join(self.upload_dir, "pubkeys")
            if os.path.exists(pubkeys_dir):
                for f in os.listdir(pubkeys_dir):
                    os.remove(os.path.join(pubkeys_dir, f))
                os.rmdir(pubkeys_dir)
            if os.path.exists(self.upload_dir):
                for f in os.listdir(self.upload_dir):
                    os.remove(os.path.join(self.upload_dir, f))
                os.rmdir(self.upload_dir)

    def send_and_receive(self, payload):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', self.port))
            sock.sendall(json.dumps(payload).encode('utf-8') + b'\n')
            response_bytes = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response_bytes += chunk
                if b'\n' in chunk:
                    break
            return json.loads(response_bytes.decode('utf-8').strip())

    # 1. Happy fetch
    def test_happy_fetch(self):
        # Diske geçerli sertifikayı yaz
        bob_path = storage_layout.pubkey_path_for(self.upload_dir, "bob")
        valid_cert_json = {"cert_pem": base64.b64encode(self.cert_bytes).decode('utf-8')}
        with open(bob_path, "w") as f:
            json.dump(valid_cert_json, f)
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', self.port))
            
            client_session = {
                "conn": sock,
                "ca_cert": self.ca_cert
            }
            
            result = fetch_peer_cert(client_session, "bob")
            self.assertIsNotNone(result)
            self.assertIn("cert_pem", result)

    # 2. Unknown user
    def test_unknown_user(self):
        # alice.json dosyasi yok
        payload = {"action": "GET_PUBKEY", "username": "alice"}
        res = self.send_and_receive(payload)
        self.assertEqual(res["status"], "NOT_FOUND")

    # 3. Path traversal
    def test_path_traversal(self):
        malicious_usernames = [
            "../bob",
            "../../etc/passwd",
            "bob/../bob",
            "bob\0"
        ]
        
        for bad_user in malicious_usernames:
            payload = {"action": "GET_PUBKEY", "username": bad_user}
            res = self.send_and_receive(payload)
            self.assertEqual(res["status"], "NOT_FOUND", f"Path traversal failed to block: {bad_user}")

    # 4. Corrupted pubkey file
    def test_corrupted_pubkey_file(self):
        # Diske geçersiz veri (kırık json veya bad signature) yazalım
        bob_path = storage_layout.pubkey_path_for(self.upload_dir, "bob")
        with open(bob_path, "w") as f:
            f.write("THIS IS NOT A VALID JSON AND CERTAINLY NOT A VALID CERTIFICATE")
            
        payload = {"action": "GET_PUBKEY", "username": "bob"}
        res = self.send_and_receive(payload)
        # KURAL: Internal hata sizdirmamali, NOT_FOUND donmeli
        self.assertEqual(res["status"], "NOT_FOUND")
        
        # Test 2: Gecerli JSON ama imza yanlis/kirik sertifika pem
        with open(bob_path, "w") as f:
            json.dump({"cert_pem": base64.b64encode(b"FAKE_CERT").decode('utf-8')}, f)
        
        res2 = self.send_and_receive(payload)
        self.assertEqual(res2["status"], "NOT_FOUND")

if __name__ == "__main__":
    unittest.main()
