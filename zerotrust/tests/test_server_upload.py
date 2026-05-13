import unittest
import socket
import json
import base64
import time
import os
import hashlib
import threading
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from zerotrust.server.main import ZeroTrustServer, ZeroTrustRequestHandler
import zerotrust.server.handler as handler

class TestServerUpload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Gercekci imza ve cert icin CA ve entity hazirla
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA")])
        cls.ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            cls.ca_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(cls.ca_key, hashes.SHA256())

        cls.client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        c_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"client_user")])
        cls.client_cert = x509.CertificateBuilder().subject_name(c_sub).issuer_name(issuer).public_key(
            cls.client_key.public_key()).serial_number(2).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)).sign(cls.ca_key, hashes.SHA256())

        cls.cert_bytes = cls.client_cert.public_bytes(serialization.Encoding.PEM)

    def setUp(self):
        handler.SEEN_NONCES.clear()
        
        self.upload_dir = f"server_data_test_{uuid.uuid4()}"
        os.makedirs(self.upload_dir, exist_ok=True)
        self.server_state = {"upload_dir": self.upload_dir}
        self.server = ZeroTrustServer(('127.0.0.1', 0), ZeroTrustRequestHandler, self.server_state)
        self.port = self.server.server_address[1]
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        
        # Cleanup created dummy files
        if os.path.exists(self.upload_dir):
            for f in os.listdir(self.upload_dir):
                os.remove(os.path.join(self.upload_dir, f))
            os.rmdir(self.upload_dir)

    def generate_payload(self, sender="client_user", recipient="target_user", timestamp=None, 
                         tamper_cipher=False, forged_signature=False, explicit_nonce=None):
        if timestamp is None:
            timestamp = time.time()
            
        nonce = explicit_nonce or os.urandom(16).hex()
        ciphertext = b"Secret File Content"
        wrapped_key = b"Wrapped AES Key"
        
        if tamper_cipher:
            ciphertext = b"Tampered Content"

        c_hash = hashlib.sha256(b"Secret File Content").hexdigest()
        w_hash = hashlib.sha256(wrapped_key).hexdigest()
        
        canonical_str = f"{sender}|{recipient}|{timestamp}|{nonce}|{c_hash}|{w_hash}"
        
        sig_key = rsa.generate_private_key(65537, 2048) if forged_signature else self.client_key
        signature = sig_key.sign(
            canonical_str.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        return {
            "action": "UPLOAD",
            "mock_session_subject": "client_user",  # simulates session context
            "mock_session_cert": base64.b64encode(self.cert_bytes).decode('utf-8'),
            "sender": sender,
            "recipient": recipient,
            "timestamp": timestamp,
            "nonce": nonce,
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "wrapped_key": base64.b64encode(wrapped_key).decode('utf-8'),
            "ciphertext_sha256": c_hash,
            "wrapped_key_sha256": w_hash,
            "signature": base64.b64encode(signature).decode('utf-8')
        }

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
            return json.loads(response_bytes.decode('utf-8').strip())

    # 1. Happy path
    def test_upload_happy_path(self):
        payload = self.generate_payload()
        res = self.send_and_receive(payload)
        self.assertEqual(res["status"], "UPLOAD_ACK")
        self.assertIn("file_id", res)
        
        # Verify file is on disk
        file_path = os.path.join(self.upload_dir, res["file_id"])
        self.assertTrue(os.path.exists(file_path))

    # 2. Tampered ciphertext
    def test_upload_tampered_ciphertext(self):
        payload = self.generate_payload(tamper_cipher=True)
        res = self.send_and_receive(payload)
        self.assertEqual(res["status"], "AUTH_FAILED")
        
        # Verify NO file is on disk
        self.assertEqual(len(os.listdir(self.upload_dir)), 0)

    # 3. Forged signature
    def test_upload_forged_signature(self):
        payload = self.generate_payload(forged_signature=True)
        res = self.send_and_receive(payload)
        self.assertEqual(res["status"], "AUTH_FAILED")

    # 4. Stale timestamp
    def test_upload_stale_timestamp(self):
        stale_time = time.time() - 50
        payload = self.generate_payload(timestamp=stale_time)
        res = self.send_and_receive(payload)
        self.assertEqual(res["status"], "STALE")

    # 5. Replayed nonce
    def test_upload_replayed_nonce(self):
        nonce = "duplicate_nonce_123"
        payload = self.generate_payload(explicit_nonce=nonce)
        res1 = self.send_and_receive(payload)
        self.assertEqual(res1["status"], "UPLOAD_ACK")
        
        # Replay same payload
        res2 = self.send_and_receive(payload)
        self.assertEqual(res2["status"], "REPLAY")

    # 6. Unknown recipient
    def test_upload_unknown_recipient(self):
        payload = self.generate_payload(recipient="unknown_user")
        res = self.send_and_receive(payload)
        self.assertEqual(res["status"], "NOT_FOUND")

if __name__ == "__main__":
    unittest.main()
