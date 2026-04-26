import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import client
import server


class ServerCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_packages_dir = server.PACKAGES_DIR
        self.original_metadata_file = server.METADATA_FILE

        storage_root = Path(self.temp_dir.name)
        server.PACKAGES_DIR = str(storage_root / "packages")
        server.METADATA_FILE = str(storage_root / "metadata.json")

        self.sender_key = client.load_private_key("client1_private.pem")
        self.sender_cert = client.load_certificate("client1_cert.pem")
        self.recipient_cert = client.load_certificate("client2_cert.pem")

    def tearDown(self):
        server.PACKAGES_DIR = self.original_packages_dir
        server.METADATA_FILE = self.original_metadata_file
        self.temp_dir.cleanup()

    def build_package(self, recipient="client2", expires_in_hours=1):
        plaintext = b"server command test"
        file_key = AESGCM.generate_key(bit_length=256)
        nonce = b"servernonce1"
        ciphertext = AESGCM(file_key).encrypt(nonce, plaintext, None)
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
            "recipient": recipient,
            "filename": "../unsafe-name.txt",
            "expires_at": expires_at,
            "file_hash": client.sha256_b64(plaintext),
            "file_nonce": client.b64e(nonce),
            "ciphertext": client.b64e(ciphertext),
            "ciphertext_hash": client.sha256_b64(ciphertext),
            "wrapped_key": client.b64e(wrapped_key),
        }
        package["signature"] = client.b64e(client.sign_package(package, self.sender_key))
        return package

    def upload_package(self, package):
        response = server.handle_upload(
            {"type": "UPLOAD", "package": package},
            "client1",
            self.sender_cert,
        )
        self.assertEqual(response["status"], "OK")
        return response["file_id"]

    def test_list_pending_only_returns_files_for_authenticated_recipient(self):
        file_id = self.upload_package(self.build_package(recipient="client2"))

        client2_list = server.handle_list_pending("client2")
        self.assertEqual(client2_list["status"], "OK")
        self.assertEqual([item["file_id"] for item in client2_list["files"]], [file_id])

        client1_list = server.handle_list_pending("client1")
        self.assertEqual(client1_list["status"], "OK")
        self.assertEqual(client1_list["files"], [])

    def test_download_requires_authenticated_recipient(self):
        file_id = self.upload_package(self.build_package(recipient="client2"))

        rejected = server.handle_download({"file_id": file_id}, "client1")
        self.assertEqual(rejected["status"], "ERROR")
        self.assertIn("yetkiniz", rejected["error"])

        accepted = server.handle_download({"file_id": file_id}, "client2")
        self.assertEqual(accepted["status"], "OK")
        self.assertEqual(accepted["package"]["file_id"], file_id)

    def test_expired_metadata_is_hidden_from_pending_list_and_download(self):
        file_id = self.upload_package(self.build_package(recipient="client2"))
        metadata = server.load_metadata()
        metadata[0]["expires_at"] = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        server.save_metadata(metadata)

        list_response = server.handle_list_pending("client2")
        self.assertEqual(list_response["status"], "OK")
        self.assertEqual(list_response["files"], [])

        download_response = server.handle_download({"file_id": file_id}, "client2")
        self.assertEqual(download_response["status"], "ERROR")
        self.assertIn("expired", download_response["error"])

    def test_upload_sanitizes_filename_before_storage(self):
        file_id = self.upload_package(self.build_package(recipient="client2"))
        metadata = server.load_metadata()

        self.assertEqual(metadata[0]["file_id"], file_id)
        self.assertEqual(metadata[0]["filename"], "unsafe-name.txt")


if __name__ == "__main__":
    unittest.main()
