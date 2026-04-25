import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import client
import server


class SecureFileFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_packages_dir = server.PACKAGES_DIR
        self.original_metadata_file = server.METADATA_FILE

        storage_root = Path(self.temp_dir.name)
        server.PACKAGES_DIR = str(storage_root / "packages")
        server.METADATA_FILE = str(storage_root / "metadata.json")

        self.sender_key = client.load_private_key("client1_private.pem")
        self.sender_cert = client.load_certificate("client1_cert.pem")
        self.recipient_key = client.load_private_key("client2_private.pem")
        self.recipient_cert = client.load_certificate("client2_cert.pem")
        self.ca_cert = client.load_certificate("ca_cert.pem")

    def tearDown(self):
        server.PACKAGES_DIR = self.original_packages_dir
        server.METADATA_FILE = self.original_metadata_file
        self.temp_dir.cleanup()

    def build_package(self, plaintext=b"secret test file", expires_in_hours=1):
        file_key = AESGCM.generate_key(bit_length=256)
        file_nonce = b"123456789012"
        ciphertext = AESGCM(file_key).encrypt(file_nonce, plaintext, None)
        wrapped_key = self.recipient_cert.public_key().encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        expires_at = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(hours=expires_in_hours)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

        package = {
            "sender": "client1",
            "recipient": "client2",
            "filename": "message.txt",
            "expires_at": expires_at,
            "file_hash": client.sha256_b64(plaintext),
            "file_nonce": client.b64e(file_nonce),
            "ciphertext": client.b64e(ciphertext),
            "ciphertext_hash": client.sha256_b64(ciphertext),
            "wrapped_key": client.b64e(wrapped_key),
        }
        package["signature"] = client.b64e(client.sign_package(package, self.sender_key))
        return package, plaintext

    def test_upload_list_download_decrypts_and_verifies_signature(self):
        package, original_plaintext = self.build_package()

        upload_response = server.handle_upload(
            {"type": "UPLOAD", "package": package},
            "client1",
            self.sender_cert,
        )
        self.assertEqual(upload_response["status"], "OK")
        file_id = upload_response["file_id"]

        list_response = server.handle_list_pending("client2")
        self.assertEqual(list_response["status"], "OK")
        self.assertEqual(len(list_response["files"]), 1)
        self.assertEqual(list_response["files"][0]["file_id"], file_id)

        unauthorized_response = server.handle_download({"file_id": file_id}, "client1")
        self.assertEqual(unauthorized_response["status"], "ERROR")

        download_response = server.handle_download({"file_id": file_id}, "client2")
        self.assertEqual(download_response["status"], "OK")
        downloaded_package = download_response["package"]

        sender_cert = client.x509.load_pem_x509_certificate(
            client.b64d(downloaded_package["sender_cert"])
        )
        self.assertTrue(client.verify_certificate_chain(sender_cert, self.ca_cert))
        client.verify_package_signature(downloaded_package, sender_cert)

        unwrapped_key = self.recipient_key.decrypt(
            client.b64d(downloaded_package["wrapped_key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        plaintext = AESGCM(unwrapped_key).decrypt(
            client.b64d(downloaded_package["file_nonce"]),
            client.b64d(downloaded_package["ciphertext"]),
            None,
        )
        self.assertEqual(plaintext, original_plaintext)
        self.assertEqual(client.sha256_b64(plaintext), downloaded_package["file_hash"])

    def test_expired_upload_is_rejected(self):
        package, _ = self.build_package(expires_in_hours=-1)

        upload_response = server.handle_upload(
            {"type": "UPLOAD", "package": package},
            "client1",
            self.sender_cert,
        )

        self.assertEqual(upload_response["status"], "ERROR")
        self.assertIn("Expiration", upload_response["error"])


if __name__ == "__main__":
    unittest.main()
